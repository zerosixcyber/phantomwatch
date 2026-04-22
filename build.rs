use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "bpf/exec_tracker.bpf.c";

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));

    let skel_path = out_dir.join("exec_tracker.skel.rs");

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args(["-I", "bpf/include", "-Wno-missing-declarations"])
        .build_and_generate(&skel_path)
        .expect("failed to build and generate BPF skeleton");

    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo::rerun-if-changed=bpf/include/common.h");
}
