use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::time::Instant;

#[allow(dead_code)]
pub struct ProcessState {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub ptrace_target: Option<u32>,

    pub has_external_connect: bool,
    pub connect_addr: Option<(Ipv4Addr, u16)>,
    pub stdin_redirected: bool,
    pub stdout_redirected: bool,
    pub stderr_redirected: bool,
    pub has_memfd: bool,
    pub exec_on_memfd: bool,
}

impl ProcessState {
    fn new(pid: u32, ppid: u32, uid: u32, comm: String) -> Self {
        let now = Instant::now();
        Self {
            pid,
            ppid,
            uid,
            comm,
            first_seen: now,
            last_seen: now,
            has_external_connect: false,
            connect_addr: None,
            stdin_redirected: false,
            stdout_redirected: false,
            stderr_redirected: false,
            has_memfd: false,
            exec_on_memfd: false,
            ptrace_target: None,
        }
    }
}

#[derive(Serialize)]
pub struct Alert {
    pub version: &'static str,
    pub detector: &'static str,
    pub detector_version: &'static str,
    pub timestamp: String,
    pub hostname: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub mitre: Vec<String>,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub details: String,
}

pub struct Correlator {
    states: HashMap<u32, ProcessState>,
    ttl_seconds: u64,
}

impl Correlator {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            states: HashMap::new(),
            ttl_seconds,
        }
    }

    fn get_or_create(&mut self, pid: u32, ppid: u32, uid: u32, comm: &str) -> &mut ProcessState {
        self.states
            .entry(pid)
            .and_modify(|s| {
                s.last_seen = Instant::now();
            })
            .or_insert_with(|| ProcessState::new(pid, ppid, uid, comm.to_string()))
    }

    pub fn handle_connect(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        addr: Ipv4Addr,
        port: u16,
    ) {
        let state = self.get_or_create(pid, ppid, uid, comm);
        state.has_external_connect = true;
        state.connect_addr = Some((addr, port));
    }

    pub fn handle_dup2(&mut self, pid: u32, ppid: u32, uid: u32, comm: &str, newfd: i32) {
        let state = self.get_or_create(pid, ppid, uid, comm);
        match newfd {
            0 => state.stdin_redirected = true,
            1 => state.stdout_redirected = true,
            2 => state.stderr_redirected = true,
            _ => {}
        }
    }

    pub fn handle_exec(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        filename: &str,
        argv: &str,
    ) -> Option<Alert> {
        if argv.contains("/dev/tcp/") || argv.contains("/dev/udp") {
            return Some(Alert {
                version: "1.0",
                detector: "phantomwatch",
                detector_version: env!("CARGO_PKG_VERSION"),
                timestamp: chrono::Utc::now().to_rfc3339(),
                hostname: gethostname(),
                rule_id: "PW-002".to_string(),
                rule_name: "Bash /dev/tcp Reverse Shell".to_string(),
                severity: "critical".to_string(),
                mitre: vec!["T1059.004".to_string()],
                pid,
                ppid,
                uid,
                comm: comm.to_string(),
                details: format!("execve with /dev/tcp in argv: {}", argv),
            });
        }

        let state = self.states.get(&pid)?;

        if !state.has_external_connect {
            return None;
        }

        if !state.stdin_redirected || !state.stdout_redirected || !state.stderr_redirected {
            return None;
        }

        let shells = [
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "/bin/dash",
            "/bin/ash",
            "/usr/bin/sh",
            "/usr/bin/bash",
            "/usr/bin/zsh",
            "/usr/bin/dash",
        ];

        if !shells.iter().any(|s| filename.starts_with(s)) {
            return None;
        }

        let (addr, port) = state.connect_addr.unwrap_or((Ipv4Addr::UNSPECIFIED, 0));

        Some(Alert {
            version: "1.0",
            detector: "phantomwatch",
            detector_version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname(),
            rule_id: "PW-001".to_string(),
            rule_name: "Classic Reverse Shell".to_string(),
            severity: "critical".to_string(),
            mitre: vec!["T1059.004".to_string()],
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: format!("Reverse shell to {}:{}", addr, port),
        })
    }

    pub fn handle_memfd(&mut self, pid: u32, ppid: u32, uid: u32, comm: &str) {
        let state = self.get_or_create(pid, ppid, uid, comm);
        state.has_memfd = true;
    }

    pub fn handle_execveat(&mut self, pid: u32, ppid: u32, uid: u32, comm: &str) -> Option<Alert> {
        let state = self.states.get(&pid)?;

        if !state.has_memfd {
            return None;
        }

        Some(Alert {
            version: "1.0",
            detector: "phantomwatch",
            detector_version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname(),
            rule_id: "PW-003".to_string(),
            rule_name: "Fileless Execution via memfd".to_string(),
            severity: "critical".to_string(),
            mitre: vec!["T1055.009".to_string()],
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: "execveat(AT_EMPTY_PATH) after memfd_create -- in-memory ELF execution"
                .to_string(),
        })
    }

    pub fn handle_ptrace(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        target_pid: u32,
    ) -> Option<Alert> {
        let debuggers = ["gdb", "lldb", "strace", "ltrace", "perf"];

        if debuggers.iter().any(|d| comm.starts_with(d)) {
            return None;
        }

        if pid == target_pid {
            return None;
        }

        let state = self.get_or_create(pid, ppid, uid, comm);
        state.ptrace_target = Some(target_pid);

        Some(Alert {
            version: "1.0",
            detector: "phantomwatch",
            detector_version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname(),
            rule_id: "PW-004".to_string(),
            rule_name: "Process Injection via ptrace".to_string(),
            severity: "high".to_string(),
            mitre: vec!["T1055.008".to_string()],
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: format!("ptrace ATTACH to pid{}", target_pid),
        })
    }

    pub fn handle_vm_writev(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        target_pid: u32,
    ) -> Option<Alert> {
        Some(Alert {
            version: "1.0",
            detector: "phantomwatch",
            detector_version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname(),
            rule_id: "PW-005".to_string(),
            rule_name: "Cross-Process Memory Write".to_string(),
            severity: "high".to_string(),
            mitre: vec!["T1055".to_string()],
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: format!("process_vm_writev to pid {}", target_pid),
        })
    }

    pub fn handle_file_open(
        &mut self,
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: &str,
        path: &str,
    ) -> Option<Alert> {
        // Check if path matches /proc/<pid>/mem
        if !path.ends_with("/mem") {
            return None;
        }

        // Extract target PID from path: /proc/<pid>/mem
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 4 || parts[1] != "proc" {
            return None;
        }

        let target_pid: u32 = match parts[2].parse() {
            Ok(p) => p,
            Err(_) => return None,
        };

        // Ignore self-access
        if target_pid == pid {
            return None;
        }

        Some(Alert {
            version: "1.0",
            detector: "phantomwatch",
            detector_version: env!("CARGO_PKG_VERSION"),
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: gethostname(),
            rule_id: "PW-006".to_string(),
            rule_name: "/proc/pid/mem Write".to_string(),
            severity: "high".to_string(),
            mitre: vec!["T1055".to_string()],
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: format!("write access to {} (target pid {})", path, target_pid),
        })
    }

    pub fn cleanup_stale(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.ttl_seconds);
        self.states.retain(|_, s| s.last_seen > cutoff);
    }
}

fn gethostname() -> String {
    nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
