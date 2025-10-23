// Reference: https://pyo3.rs/v0.27.1/building-and-distribution.html?highlight=build.rs#macos
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}