#[cfg(not(all(windows, target_arch = "x86_64")))]
compile_error!("zeron-sandboxie-bridge supports x86_64 Windows only");

#[cfg(all(windows, target_arch = "x86_64"))]
mod native;

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() {
    std::process::exit(native::run());
}
