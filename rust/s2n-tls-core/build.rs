fn main() {
    // Tell cargo to pass the library location to dependents
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:root={}", out_dir);
}
