use std::env;
use std::path::PathBuf;

fn main() {
    // Configure and generate bindings.
    let bindings = bindgen::builder()
        .use_core()

        //.blocklist_type("embedded_panic_header") //https://github.com/MozhuCY/osx-sys/commit/4f7265b6757499355696e4e5d1a991ee9a26dbfb
        //.blocklist_type("embedded_panic_header__bindgen_ty_1")

        .blocklist_type("IMAGE_TLS_DIRECTORY") //https://github.com/Rust-SDL2/rust-sdl2/issues/1288
        .blocklist_type("PIMAGE_TLS_DIRECTORY")
        .blocklist_type("IMAGE_TLS_DIRECTORY64")
        .blocklist_type("PIMAGE_TLS_DIRECTORY64")
        .blocklist_type("_IMAGE_TLS_DIRECTORY64")

        .header("../inc/Storage.h")
        //.clang_arg("-x").clang_arg("c++")
        .generate()
        .expect("Couldn't write bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Write the generated bindings to an output file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))//"../inc/libnet.rs" 好家伙生成的文件达20多MB，66万行之多，运行也得几分钟。
        .expect("Couldn't write bindings!");

        //相当于：#[link(name = "..\\x64\\Debug\\Storage")]，此办法经测试有效。
        println!("cargo:rustc-link-search=native={}", "..\\x64\\Debug");
        println!("cargo:rustc-link-lib=dylib=Storage");
        println!("cargo:rerun-if-changed=../inc/Storage.h");

        // cxx_build::bridge("src/main.rs")  // returns a cc::Build
        // .file("../inc/libnet.h")
        // .flag_if_supported("-std=c++11")
        // .compile("cxxbridge-demo");
}
