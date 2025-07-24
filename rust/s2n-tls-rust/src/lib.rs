pub use s2n_tls_events::ffi::ffi::c_api::*;

#[unsafe(no_mangle)]
pub extern "C" fn rust_function() {
    println!("Hello from Rust!");
}
