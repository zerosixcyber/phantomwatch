# Phantomwatch

eBPF-based fileless malware detector for Linux.

Phantomwatch uses eBPF to observe syscall sequences directly in the Linux kernel and detects fileless attack techniques in real time — reverse shells, in-memory execution, process injection, and more.

Single binary. No Kubernetes required. No cloud dependency.

## Detection Rules

| ID | Name | MITRE ATT&CK | Severity |
|----|------|-------------|----------|
| PW-001 | Classic Reverse Shell | T1059.004 | Critical |
| PW-002 | Bash /dev/tcp Reverse Shell | T1059.004 | Critical |
| PW-003 | Fileless Execution via memfd | T1055.009 | Critical |

## Quick Start

```bash
# Check kernel compatibility
sudo ./phantomwatch check

# Start the detector (alerts on stdout as JSON)
sudo ./phantomwatch run

# Start with debug logging
sudo RUST_LOG=debug ./phantomwatch run
```

## Building from Source

Requirements: Rust 1.75+, Clang 14+, bpftool, Linux kernel 5.15+

```bash
# Install dependencies (Fedora)
sudo dnf install clang llvm bpftool elfutils-libelf-devel zlib-devel kernel-devel-matched libbpf-devel

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
git clone https://github.com/zerosixcyber/phantomwatch.git
cd phantomwatch
cargo build --release
```

## Kernel Requirements

- Minimum: Linux 5.15 (Ubuntu 22.04)
- Recommended: Linux 6.1+ (Debian 12, Ubuntu 24.04, Fedora 40+)
- BPF-LSM must be enabled (`bpf` in `/sys/kernel/security/lsm`)

## Alert Format

Alerts are structured JSON on stdout:

```json
{
  "version": "1.0",
  "detector": "phantomwatch",
  "detector_version": "0.1.0",
  "timestamp": "2026-04-27T06:11:42.600Z",
  "hostname": "web-prod-01",
  "rule_id": "PW-001",
  "rule_name": "Classic Reverse Shell",
  "severity": "critical",
  "mitre": ["T1059.004"],
  "pid": 1234,
  "ppid": 999,
  "uid": 1000,
  "comm": "bash",
  "details": "Reverse shell to 1.2.3.4:4444"
}
```

## How It Works

Phantomwatch attaches eBPF programs to kernel tracepoints and LSM hooks. When a process makes a syscall — opening a socket, duplicating a file descriptor, executing a binary — the eBPF program captures the event and pushes it to a ring buffer.

A user-space correlator maintains per-process state and matches syscall sequences against detection rules. When a pattern matches (e.g., `socket` → `connect(external)` → `dup2(fd→0,1,2)` → `execve(shell)`), a structured JSON alert is emitted.

## License

- Kernel-side eBPF code (`bpf/`): `GPL-2.0-only OR BSD-3-Clause`
- User-space code (`src/`): `Apache-2.0 OR MIT`

## Disclaimer

This software is provided "as is" for defensive security purposes on systems the operator is authorized to monitor. The author assumes no liability for missed detections, false positives, system instability, or damages resulting from its use.
