fn main() {
    let proto_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let proto = proto_dir.join("tunnet/agent.proto");
    println!("cargo:rerun-if-changed={}", proto.display());

    let fds = protox::compile([&proto], [&proto_dir]).expect("compile tunnet.agent proto");
    prost_build::Config::new()
        .compile_fds(fds)
        .expect("generate prost bindings");
}
