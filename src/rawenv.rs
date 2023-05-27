use std::{any::Any};

use icicle_vm::{VmExit};
use icicle_vm::cpu::{Cpu, Environment, debug_info::{DebugInfo, SourceLocation}};
use icicle_vm::cpu::mem::{AllocLayout, Mapping, perm};

pub struct RawEnvironment {
    debug_info: DebugInfo,
}

impl RawEnvironment {
    pub fn new() -> Self {
        Self { debug_info: DebugInfo::default() }
    }
}

/*impl ElfLoader for RawEnvironment {
    const DYNAMIC_MEMORY: bool = true;
}*/

impl Environment for RawEnvironment {
    fn load(&mut self, cpu: &mut Cpu, code_bytes: &[u8]) -> Result<(), String> {
        let layout = AllocLayout { addr: Some(0x10000), size: 0x1000, align: 0x1000 };

        let base_addr = cpu
            .mem
            .alloc_memory(layout, Mapping { perm: perm::MAP, value: 0xaa })
            .map_err(|e| format!("Failed to allocate memory: {e:?}"))?;

        // NOTE: without READ we cannot translate the code and a confusing exception is raised
        cpu.mem.update_perm(layout.addr.unwrap(), layout.size, perm::EXEC | perm::READ)
            .map_err(|e| format!("Failed to update perm: {e:?}"))?;

        cpu.mem.write_bytes(base_addr, code_bytes, perm::NONE)
            .map_err(|e|format!("Failed to write memory: {e:?}"))?;

        (cpu.arch.on_boot)(cpu, base_addr);

        Ok(())
    }

    fn handle_exception(&mut self, _: &mut Cpu) -> Option<VmExit> {
        None
    }

    fn symbolize_addr(&mut self, _: &mut Cpu, addr: u64) -> Option<SourceLocation> {
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        self.debug_info.symbols.resolve_sym(symbol)
    }

    fn snapshot(&mut self) -> Box<dyn Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn Any>) {}
}