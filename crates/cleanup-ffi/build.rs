fn main() {
    // Compile the Objective-C hardware info reader (reads IOKit HW identifiers
    // needed for Apple IDS authentication — serial, UUID, ROM, MLB, etc.)
    cc::Build::new()
        .file("src/hardware_info.m")
        .flag("-fobjc-arc")
        .flag("-framework")
        .flag("Foundation")
        .flag("-framework")
        .flag("IOKit")
        .compile("hardware_info");

    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=IOKit");
}
