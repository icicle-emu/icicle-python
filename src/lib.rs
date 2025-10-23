use std::borrow::Cow;
use std::collections::HashMap;
use icicle_cpu::mem::{Mapping, MemError, perm};
use icicle_cpu::{Cpu, ExceptionCode, ValueSource, VmExit};
use pyo3::prelude::*;
use pyo3::exceptions::*;
use indexmap::IndexMap;
use target_lexicon::Architecture;
use sleigh_runtime::NamedRegister;

// References:
// - https://pyo3.rs/main/conversions/tables
// - https://pyo3.rs/main/class

struct X86FlagsRegHandler {
    pub eflags: pcode::VarNode,
}

impl icicle_cpu::RegHandler for X86FlagsRegHandler {
    fn read(&mut self, cpu: &mut Cpu) {
        let eflags = icicle_vm::x86::eflags(cpu);
        cpu.write_var::<u32>(self.eflags, eflags);
    }

    fn write(&mut self, cpu: &mut Cpu) {
        let eflags = cpu.read_var::<u32>(self.eflags);
        icicle_vm::x86::set_eflags(cpu, eflags);
    }
}

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteOnly,
    ExecuteRead,
    ExecuteReadWrite,
}

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum RunStatus {
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

#[pyclass(eq, eq_int, module = "icicle")]
#[derive(Clone, Debug, PartialEq)]
pub enum MemoryExceptionCode {
    Unallocated,
    Unmapped,
    UnmappedRegister,
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

impl From<MemError> for MemoryExceptionCode {
    fn from(value: MemError) -> Self {
        match value {
            MemError::Unallocated => MemoryExceptionCode::Unallocated,
            MemError::Unmapped => MemoryExceptionCode::Unmapped,
            MemError::UnmappedRegister => MemoryExceptionCode::UnmappedRegister,
            MemError::Uninitalized => MemoryExceptionCode::Uninitialized,
            MemError::ReadViolation => MemoryExceptionCode::ReadViolation,
            MemError::WriteViolation => MemoryExceptionCode::WriteViolation,
            MemError::ExecViolation => MemoryExceptionCode::ExecViolation,
            MemError::ReadWatch => MemoryExceptionCode::ReadWatch,
            MemError::WriteWatch => MemoryExceptionCode::WriteWatch,
            MemError::Unaligned => MemoryExceptionCode::Unaligned,
            MemError::OutOfMemory => MemoryExceptionCode::OutOfMemory,
            MemError::SelfModifyingCode => MemoryExceptionCode::SelfModifyingCode,
            MemError::AddressOverflow => MemoryExceptionCode::AddressOverflow,
            MemError::Unknown => MemoryExceptionCode::Unknown,
        }
    }
}

#[pyclass(eq, eq_int, module = "icicle", name = "ExceptionCode")]
#[derive(Clone, Debug, PartialEq)]
pub enum ExceptionCodePy {
    NoException = 0x0000,

    InstructionLimit = 0x0001,
    Halt = 0x0002,
    Sleep = 0x0003,
    SoftwareBreakpoint = 0x0004,

    Syscall = 0x0101,
    CpuStateChanged = 0x0102,
    DivisionException = 0x0103,

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
    ExecUnaligned = 0x0403,

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
    UnmappedRegister = 0x3003,

    UnknownError,
}

impl From<ExceptionCode> for ExceptionCodePy {
    fn from(value: ExceptionCode) -> Self {
        match value {
            ExceptionCode::None => ExceptionCodePy::NoException,
            ExceptionCode::InstructionLimit => ExceptionCodePy::InstructionLimit,
            ExceptionCode::Halt => ExceptionCodePy::Halt,
            ExceptionCode::Sleep => ExceptionCodePy::Sleep,
            ExceptionCode::SoftwareBreakpoint => ExceptionCodePy::SoftwareBreakpoint,
            ExceptionCode::Syscall => ExceptionCodePy::Syscall,
            ExceptionCode::CpuStateChanged => ExceptionCodePy::CpuStateChanged,
            ExceptionCode::DivisionException => ExceptionCodePy::DivisionException,
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
            ExceptionCode::UnmappedRegister => ExceptionCodePy::UnmappedRegister,
            ExceptionCode::UnknownError => ExceptionCodePy::UnknownError,
        }
    }
}

#[allow(non_snake_case)]
fn raise_MemoryException(message: String, e: MemError) -> PyErr {
    Python::attach(|py| {
        let icicle = py.import("icicle").unwrap();
        let exception = icicle.getattr("MemoryException").unwrap();
        let args = (message, MemoryExceptionCode::from(e));
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
pub struct Icicle {
    architecture: String,
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
}

fn reg_find<'a>(i: &'a Icicle, name: &str) -> PyResult<&'a NamedRegister> {
    let sleigh = &i.vm.cpu.arch.sleigh;
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

fn reg_var<'a>(i: &'a Icicle, name: &str) -> PyResult<pcode::VarNode> {
    let var = reg_find(i, name)?.get_var();
    var.ok_or(PyKeyError::new_err(format!("Register var too large: {name}")))
}

#[pymethods]
impl Icicle {
    #[getter]
    pub fn get_icount_limit(&mut self) -> u64 {
        self.vm.icount_limit
    }

    #[setter]
    pub fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    #[getter]
    pub fn get_icount(&mut self) -> u64 {
        self.vm.cpu.icount
    }

    #[setter]
    pub fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    #[getter]
    pub fn get_exception_code(&self) -> ExceptionCodePy {
        ExceptionCode::from_u32(self.vm.cpu.exception.code).into()
    }

    #[getter]
    pub fn get_exception_value(&self) -> u64 {
        self.vm.cpu.exception.value
    }

    #[getter]
    pub fn get_architecture(&self) -> String {
        self.architecture.to_string()
    }

    #[getter]
    pub fn get_pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    #[setter]
    pub fn set_pc(&mut self, address: u64) {
        self.vm.cpu.write_pc(address)
    }

    #[getter]
    pub fn get_sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.vm.cpu.arch.reg_sp)
    }

    #[setter]
    pub fn set_sp(&mut self, address: u64) {
        self.vm.cpu.write_reg(self.vm.cpu.arch.reg_sp, address)
    }

    #[getter]
    pub fn get_mem_capacity(&self) -> usize {
        self.vm.cpu.mem.capacity()
    }

    #[setter]
    pub fn set_mem_capacity(&mut self, capacity: usize) -> PyResult<()> {
        if self.vm.cpu.mem.set_capacity(capacity) {
            return Ok(());
        }
        Err(
            raise_MemoryException(
                format!("Reducing memory capacity is not supported"),
                MemError::Unknown,
            )
        )
    }

    #[new]
    #[pyo3(signature = (
        architecture,
        jit = true,
        jit_mem = true,
        shadow_stack = false,
        recompilation = true,
        track_uninitialized = false,
        optimize_instructions = true,
        optimize_block = false,
        tracing = false,
    ))]
    pub fn new(
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

        // Set up the CPU state for the target triple
        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-none").as_str()
        );
        if config.triple.architecture == Architecture::Unknown {
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

        let mut vm = icicle_vm::build(&config)
            .map_err(|e| {
                PyException::new_err(format!("VM build error: {e}"))
            })?;

        // Populate the lowercase register map
        let mut regs = HashMap::new();
        let sleigh = &vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        // Special handling for x86 flags
        match config.triple.architecture {
            Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
                let eflags = sleigh.get_reg("eflags").unwrap().get_var().unwrap();
                let reg_handler = X86FlagsRegHandler { eflags };
                vm.cpu.add_reg_handler(eflags.id, Box::new(reg_handler));
            }
            _ => {}
        }

        Ok(Icicle {
            architecture,
            vm,
            regs,
        })
    }

    pub fn __str__(&mut self) -> String {
        let arch = &self.vm.cpu.arch;
        let endianness = if arch.sleigh.big_endian {
            "big endian"
        } else {
            "little endian"
        };
        format!("Icicle VM for {0:?} ({endianness})", self.architecture)
    }

    pub fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> PyResult<()> {
        let init_perm = if self.vm.cpu.mem.track_uninitialized { perm::NONE } else { perm::INIT };
        let mapping = Mapping {
            perm: convert_protection(protection) | init_perm,
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(
                raise_MemoryException(
                    format!("Failed to map memory {address:X}[{size:X}]"),
                    MemError::Unknown,
                )
            )
        }
    }

    pub fn mem_unmap(&mut self, address: u64, size: u64) -> PyResult<()> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(
                raise_MemoryException(
                    format!("Failed to unmap memory {address:X}[{size:X}]"),
                    MemError::Unknown,
                )
            )
        }
    }

    pub fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> PyResult<()> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to protect memory {address:X}[{size:X}]"),
                    e,
                )
            })?;
        Ok(())
    }

    pub fn mem_read(&mut self, address: u64, size: usize) -> PyResult<Cow<'_, [u8]>> {
        // Allocate a buffer
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);

        // Read the memory
        self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to read memory {address:X}[{size:X}]"),
                    e,
                )
            })?;
        Ok(Cow::Owned(buffer))
    }

    pub fn mem_write(&mut self, address: u64, data: Vec<u8>) -> PyResult<()> {
        let size = data.len();
        self.vm.cpu.mem.write_bytes(address, &data[..], perm::NONE)
            .map_err(|e| {
                raise_MemoryException(
                    format!("Failed to write memory {address:X}[{size:X}]"),
                    e,
                )
            })
    }

    pub fn reg_list(&self) -> PyResult<IndexMap<String, (u32, u8)>> {
        let mut result = IndexMap::new();
        let sleigh = &self.vm.cpu.arch.sleigh;
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            let var = reg.get_var();
            if let Some(var) = var {
                result.insert(name.to_string(), (reg.offset, var.size));
            }
        }
        Ok(result)
    }

    pub fn reg_offset(&self, name: &str) -> PyResult<u32> {
        Ok(reg_find(self, name)?.offset)
    }

    pub fn reg_size(&self, name: &str) -> PyResult<u8> {
        Ok(reg_var(self, name)?.size)
    }

    pub fn reg_read(&mut self, name: &str) -> PyResult<u64> {
        Ok(self.vm.cpu.read_reg(reg_var(self, name)?))
    }

    pub fn reg_write(&mut self, name: &str, value: u64) -> PyResult<()> {
        let var = reg_var(self, name)?;
        if var == self.vm.cpu.arch.reg_pc {
            self.vm.cpu.write_pc(value);
        } else {
            self.vm.cpu.write_reg(var, value);
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.vm.reset();
    }

    pub fn run(&mut self) -> RunStatus {
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

    pub fn run_until(&mut self, address: u64) -> RunStatus {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    pub fn step(&mut self, count: u64) -> RunStatus {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    pub fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    pub fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
    }
}

#[pyfunction]
pub fn architectures() -> PyResult<Vec<&'static str>> {
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
fn icicle(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(architectures, m)?)?;
    m.add_class::<Icicle>()?;
    m.add_class::<MemoryProtection>()?;
    m.add_class::<MemoryExceptionCode>()?;
    m.add_class::<RunStatus>()?;
    m.add_class::<ExceptionCodePy>()?;
    Ok(())
}