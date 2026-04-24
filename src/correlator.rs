use serde::Serialize;
use std::collections::HashMap;
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
        }
    }
}

#[derive(Serialize)]
pub struct Alert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
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
    ) -> Option<Alert> {
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
            rule_id: "PW-001".to_string(),
            rule_name: "Classic Reverse Shell".to_string(),
            severity: "critical".to_string(),
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
            rule_id: "PW-003".to_string(),
            rule_name: "Fileless Execution via memfd".to_string(),
            severity: "critical".to_string(),
            pid,
            ppid,
            uid,
            comm: comm.to_string(),
            details: "execveat(AT_EMPTY_PATH) after memfd_create -- in-memory ELF execution"
                .to_string(),
        })
    }

    pub fn cleanup_stale(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.ttl_seconds);
        self.states.retain(|_, s| s.last_seen > cutoff);
    }
}
