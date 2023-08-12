use std::borrow::Cow;
use std::collections::HashMap;
use icicle_cpu::mem::{Mapping, MemError, perm};
use icicle_cpu::{ExceptionCode, VmExit};
use pyo3::prelude::*;
use icicle_vm;
use icicle_vm::linux::LinuxCpu;
use pyo3::exceptions::*;
use target_lexicon;
use indexmap::IndexMap;
use sleigh_runtime::NamedRegister;

// References:
// - https://pyo3.rs/main/conversions/tables
// - https://pyo3.rs/main/class

#[pyclass(module = "icicle")]
#[derive(Clone)]
enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteOnly,
    ExecuteRead,
    ExecuteReadWrite,
}

#[pyclass(module = "icicle")]
#[derive(Clone)]
enum RunStatus {
    /// The VM is still running.
    Running,

    /// The VM exited because it reached instruction count limit.
    InstructionLimit,

    /// The VM exited because it reached a breakpoint.
    Breakpoint,

    /// The VM exited because the interrupt flag was set.
    Interrupted,

    /// The VM has halted.
    Halt,

    /// Killed by an environment specific mechanism.
    Killed,

    /// A deadlock was detected.
    Deadlock,

    /// MMU was unable to allocate memory for an operation.
    OutOfMemory,

    /// Internal error where the emulator reached unimplemented code.
    Unimplemented,

    /// The VM exited due to a unhandled exception.
    UnhandledException,
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

#[pyclass(module = "icicle", name = "ExceptionCode")]
#[derive(Clone)]
enum ExceptionCodePy {
    NoException = 0x0000,

    InstructionLimit = 0x0001,
    Halt = 0x0002,
    Sleep = 0x0003,

    Syscall = 0x0101,
    CpuStateChanged = 0x0102,
    DivideByZero = 0x0103,

    ReadUnmapped = 0x0201,
    ReadPerm = 0x0202,
    ReadUnaligned = 0x0203,
    ReadWatch = 0x0204,
    ReadUninitialized = 0x0205,

    WriteUnmapped = 0x0301,
    WritePerm = 0x0302,
    WriteWatch = 0x0303,
    WriteUnaligned = 0x0304,

    ExecViolation = 0x0401,
    SelfModifyingCode = 0x0402,
    ExecUnaligned = 0x0404,
    OutOfMemory = 0x0501,
    AddressOverflow = 0x0502,

    InvalidInstruction = 0x1001,
    UnknownInterrupt = 0x1002,
    UnknownCpuID = 0x1003,
    InvalidOpSize = 0x1004,
    InvalidFloatSize = 0x1005,
    CodeNotTranslated = 0x1006,
    ShadowStackOverflow = 0x1007,
    ShadowStackInvalid = 0x1008,
    InvalidTarget = 0x1009,
    UnimplementedOp = 0x100a,

    ExternalAddr = 0x2001,
    Environment = 0x2002,

    JitError = 0x3001,
    InternalError = 0x3002,

    UnknownError,
}

impl From<ExceptionCode> for ExceptionCodePy {
    fn from(value: ExceptionCode) -> Self {
        match value {
            ExceptionCode::None => ExceptionCodePy::NoException,
            ExceptionCode::InstructionLimit => ExceptionCodePy::InstructionLimit,
            ExceptionCode::Halt => ExceptionCodePy::Halt,
            ExceptionCode::Sleep => ExceptionCodePy::Sleep,
            ExceptionCode::Syscall => ExceptionCodePy::Syscall,
            ExceptionCode::CpuStateChanged => ExceptionCodePy::CpuStateChanged,
            ExceptionCode::DivideByZero => ExceptionCodePy::DivideByZero,
            ExceptionCode::ReadUnmapped => ExceptionCodePy::ReadUnmapped,
            ExceptionCode::ReadPerm => ExceptionCodePy::ReadPerm,
            ExceptionCode::ReadUnaligned => ExceptionCodePy::ReadUnaligned,
            ExceptionCode::ReadWatch => ExceptionCodePy::ReadWatch,
            ExceptionCode::ReadUninitialized => ExceptionCodePy::ReadUninitialized,
            ExceptionCode::WriteUnmapped => ExceptionCodePy::WriteUnmapped,
            ExceptionCode::WritePerm => ExceptionCodePy::WritePerm,
            ExceptionCode::WriteWatch => ExceptionCodePy::WriteWatch,
            ExceptionCode::WriteUnaligned => ExceptionCodePy::WriteUnaligned,
            ExceptionCode::ExecViolation => ExceptionCodePy::ExecViolation,
            ExceptionCode::SelfModifyingCode => ExceptionCodePy::SelfModifyingCode,
            ExceptionCode::ExecUnaligned => ExceptionCodePy::ExecUnaligned,
            ExceptionCode::OutOfMemory => ExceptionCodePy::OutOfMemory,
            ExceptionCode::AddressOverflow => ExceptionCodePy::AddressOverflow,
            ExceptionCode::InvalidInstruction => ExceptionCodePy::InvalidInstruction,
            ExceptionCode::UnknownInterrupt => ExceptionCodePy::UnknownInterrupt,
            ExceptionCode::UnknownCpuID => ExceptionCodePy::UnknownCpuID,
            ExceptionCode::InvalidOpSize => ExceptionCodePy::InvalidOpSize,
            ExceptionCode::InvalidFloatSize => ExceptionCodePy::InvalidFloatSize,
            ExceptionCode::CodeNotTranslated => ExceptionCodePy::CodeNotTranslated,
            ExceptionCode::ShadowStackOverflow => ExceptionCodePy::ShadowStackOverflow,
            ExceptionCode::ShadowStackInvalid => ExceptionCodePy::ShadowStackInvalid,
            ExceptionCode::InvalidTarget => ExceptionCodePy::InvalidTarget,
            ExceptionCode::UnimplementedOp => ExceptionCodePy::UnimplementedOp,
            ExceptionCode::ExternalAddr => ExceptionCodePy::ExternalAddr,
            ExceptionCode::Environment => ExceptionCodePy::Environment,
            ExceptionCode::JitError => ExceptionCodePy::JitError,
            ExceptionCode::InternalError => ExceptionCodePy::InternalError,
            ExceptionCode::UnknownError => ExceptionCodePy::UnknownError,
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
        MemoryProtection::ExecuteOnly => perm::EXEC,
        MemoryProtection::ExecuteRead => perm::EXEC | perm::READ,
        MemoryProtection::ExecuteReadWrite => perm::EXEC | perm::READ | perm::WRITE,
    }
}

#[pyclass(unsendable, module = "icicle")]
struct Icicle {
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
}

fn reg_find<'a>(i: &'a Icicle, name: &str) -> PyResult<&'a NamedRegister> {
    let sleigh = i.vm.cpu.sleigh();
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(name.to_lowercase().as_str())
                .ok_or(
                    PyKeyError::new_err(format!("Register not found: {name}"))
                )
        }
        Some(r) => Ok(r),
    }
}

#[pymethods]
impl Icicle {
    #[getter]
    fn get_icount_limit(&mut self) -> u64 {
        self.vm.icount_limit
    }

    #[setter]
    fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    #[getter]
    fn get_icount(&mut self) -> u64 {
        return self.vm.cpu.icount;
    }

    #[setter]
    fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    #[getter]
    fn get_exception_code(&self) -> ExceptionCodePy {
        ExceptionCode::from_u32(self.vm.cpu.exception.code).into()
    }

    #[getter]
    fn get_exception_value(&self) -> u64 {
        self.vm.cpu.exception.value
    }

    #[new]
    #[pyo3(signature = (
        architecture,
        jit = true,
        jit_mem = true,
        shadow_stack = true,
        recompilation = true,
        track_uninitialized = false,
        optimize_instructions = true,
        optimize_block = true,
        tracing = false,
    ))]
    fn new(
        architecture: String,
        jit: bool,
        jit_mem: bool,
        shadow_stack: bool,
        recompilation: bool,
        track_uninitialized: bool,
        optimize_instructions: bool,
        optimize_block: bool,
        tracing: bool,
    ) -> PyResult<Self> {
        // Prevent mixing '_' and '-'
        if architecture.split("-").count() != 1 {
            return Err(
                PyException::new_err(format!("Bad architecture format: {architecture}"))
            );
        }

        // TODO: support instantiating this multiple times
        if tracing {
            if tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .try_init().is_err() {
            }
        }

        // Setup the CPU state for the target triple
        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-none").as_str()
        );
        if config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(
                PyException::new_err(format!("Unknown architecture: {architecture}"))
            );
        }

        // Configuration
        config.enable_jit = jit;
        config.enable_jit_mem = jit_mem;
        config.enable_shadow_stack = shadow_stack;
        config.enable_recompilation = recompilation;
        config.track_uninitialized = track_uninitialized;
        config.optimize_instructions = optimize_instructions;
        config.optimize_block = optimize_block;

        let vm = icicle_vm::build(&config)
            .map_err(|e| {
                PyException::new_err(format!("VM build error: {e}"))
            })?;

        // Populate the lowercase register map
        let mut regs = HashMap::new();
        let sleigh = vm.cpu.sleigh();
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        Ok(Icicle {
            vm,
            regs,
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

    fn mem_unmap(&mut self, address: u64, size: u64) -> PyResult<()> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(
                raise_MemoryError(
                    format!("Failed to unmap memory {address:X}[{size:X}]"),
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
                    e,
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
                    e,
                )
            })
    }

    fn reg_list(&self) -> PyResult<IndexMap<String, (u32, u8)>> {
        let mut result = IndexMap::new();
        let sleigh = self.vm.cpu.sleigh();
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            result.insert(name.to_string(), (reg.offset, reg.var.size));
        }
        return Ok(result);
    }

    fn reg_offset(&self, name: &str) -> PyResult<u32> {
        Ok(reg_find(self, name)?.offset)
    }

    fn reg_size(&self, name: &str) -> PyResult<u8> {
        Ok(reg_find(self, name)?.var.size)
    }

    fn reg_read(&mut self, name: &str) -> PyResult<u64> {
        Ok(self.vm.cpu.read_reg(reg_find(self, name)?.var))
    }

    fn reg_write(&mut self, name: &str, value: u64) -> PyResult<()> {
        Ok(self.vm.cpu.write_reg(reg_find(self, name)?.var, value))
    }

    fn reset(&mut self) {
        self.vm.reset();
    }

    fn run(&mut self) -> RunStatus {
        match self.vm.run() {
            VmExit::Running => RunStatus::Running,
            VmExit::InstructionLimit => RunStatus::InstructionLimit,
            VmExit::Breakpoint => RunStatus::Breakpoint,
            VmExit::Interrupted => RunStatus::Interrupted,
            VmExit::Halt => RunStatus::Halt,
            VmExit::Killed => RunStatus::Killed,
            VmExit::Deadlock => RunStatus::Deadlock,
            VmExit::OutOfMemory => RunStatus::OutOfMemory,
            VmExit::Unimplemented => RunStatus::Unimplemented,
            VmExit::UnhandledException(_) => RunStatus::UnhandledException,
        }
    }

    fn run_until(&mut self, address: u64) -> RunStatus {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    fn step(&mut self, count: u64) -> RunStatus {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
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
fn icicle(_: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(architectures, m)?)?;
    m.add_class::<Icicle>()?;
    m.add_class::<MemoryProtection>()?;
    m.add_class::<MemoryErrorCode>()?;
    m.add_class::<RunStatus>()?;
    m.add_class::<ExceptionCodePy>()?;
    Ok(())
}