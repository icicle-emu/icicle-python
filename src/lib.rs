mod rawenv;

use std::borrow::Cow;
use std::fmt;
use std::fmt::{format, Formatter};
use icicle_cpu::mem::{Mapping, MemError, perm};
use pyo3::prelude::*;
use icicle_vm;
use icicle_vm::{BuildError, Vm};
use pyo3::types::PyList;
use pyo3::{create_exception, import_exception};
use pyo3::exceptions::PyException;
use target_lexicon;

// References:
// - https://pyo3.rs/main/conversions/tables
// - https://pyo3.rs/main/class

#[pyclass(unsendable, module = "icicle")]
struct Icicle {
    vm: icicle_vm::Vm,
}

#[pyclass(module = "icicle")]
#[derive(Clone)]
enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteRead,
    ExecuteReadWrite,
}

#[pyclass(module = "icicle")]
enum MemoryErrorCode {
    Unallocated,
    Unmapped,
    Uninitialized,
    ReadViolation,
    WriteViolation,
    ExecViolation,
    ReadWatch,
    WriteWatch,
    Unaligned,
    OutOfMemory,
    SelfModifyingCode,
    AddressOverflow,
    Unknown,
}

impl From<MemError> for MemoryErrorCode {
    fn from(value: MemError) -> Self {
        match value {
            MemError::Unallocated => MemoryErrorCode::Unallocated,
            MemError::Unmapped => MemoryErrorCode::Unmapped,
            MemError::Uninitalized => MemoryErrorCode::Uninitialized,
            MemError::ReadViolation => MemoryErrorCode::ReadViolation,
            MemError::WriteViolation => MemoryErrorCode::WriteViolation,
            MemError::ExecViolation => MemoryErrorCode::ExecViolation,
            MemError::ReadWatch => MemoryErrorCode::ReadWatch,
            MemError::WriteWatch => MemoryErrorCode::WriteWatch,
            MemError::Unaligned => MemoryErrorCode::Unaligned,
            MemError::OutOfMemory => MemoryErrorCode::OutOfMemory,
            MemError::SelfModifyingCode => MemoryErrorCode::SelfModifyingCode,
            MemError::AddressOverflow => MemoryErrorCode::AddressOverflow,
            MemError::Unknown => MemoryErrorCode::Unknown,
        }
    }
}

#[allow(non_snake_case)]
fn raise_MemoryError(message: String, e: MemError) -> PyErr {
    Python::with_gil(|py| {
        let icicle = py.import("icicle").unwrap();
        let exception = icicle.getattr("MemoryError").unwrap();
        let args = (message, MemoryErrorCode::from(e));
        let inst = exception.call1(args).unwrap();
        PyErr::from_value(inst)
    })
}

fn convert_protection(protection: MemoryProtection) -> u8 {
    match protection {
        MemoryProtection::NoAccess => perm::NONE,
        MemoryProtection::ReadOnly => perm::READ,
        MemoryProtection::ReadWrite => perm::READ | perm::WRITE,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

#[pymethods]
impl Icicle {
    #[new]
    fn new(architecture: String) -> PyResult<Self> {
        if architecture.split("-").count() != 1 {
            return Err(
                pyo3::exceptions::PyException::new_err(format!("Bad architecture format: {architecture}"))
            );
        }
        // Setup the CPU state for the target triple
        let mut cpu_config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-none").as_str()
        );
        if cpu_config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(
                pyo3::exceptions::PyException::new_err(format!("Unknown architecture: {architecture}"))
            );
        }

        // TODO: allow these to be customized
        cpu_config.enable_jit = false;
        cpu_config.enable_recompilation = false;

        let mut vm = icicle_vm::build(&cpu_config)
            .map_err(|e| {
                pyo3::exceptions::PyException::new_err(format!("VM build error: {e}"))
            })?;

        Ok(Icicle {
            vm,
        })
    }

    fn __str__(&mut self) -> String {
        let arch = &self.vm.cpu.arch;
        let endianness = if arch.sleigh.big_endian {
            "big endian"
        } else {
            "little endian"
        };
        format!("Icicle VM for {0:?} ({endianness})", arch.triple.architecture)
    }

    fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> PyResult<()> {
        let mapping = Mapping {
            perm: convert_protection(protection),
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(
                raise_MemoryError(
                    format!("Failed to map memory {address:X}[{size:X}]"),
                    MemError::Unknown,
                )
            )
        }
    }

    fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> PyResult<()> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|e| {
                raise_MemoryError(
                    format!("Failed to protect memory {address:X}[{size:X}]"),
                    e,
                )
            })?;
        Ok(())
    }

    fn mem_read(&mut self, address: u64, size: usize) -> PyResult<Cow<[u8]>> {
        // Allocate a buffer
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);

        // Read the memory
        self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryError(
                    format!("Failed to read memory {address:X}[{size:X}]"),
                    e
                )
            })?;
        return Ok(Cow::Owned(buffer));
    }

    fn mem_write(&mut self, address: u64, data: Vec<u8>) -> PyResult<()> {
        let size = data.len();
        self.vm.cpu.mem.write_bytes(address, &data[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryError(
                    format!("Failed to write memory {address:X}[{size:X}]"),
                    e
                )
            })
    }
}

#[pyfunction]
fn architectures() -> PyResult<Vec<&'static str>> {
    Ok(vec![
        "i686",
        "x86_64",
        "aarch64",
    ])
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn icicle(py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(architectures, m)?)?;
    m.add_class::<Icicle>()?;
    m.add_class::<MemoryProtection>()?;
    m.add_class::<MemoryErrorCode>()?;
    PyModule::from_code(py, r#"
class MemoryError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code
    def __str__(self):
        return f"{super().__str__()}: {self.code}"
"#, "icicle_exceptions.py", "icicle")?;
    Ok(())
}