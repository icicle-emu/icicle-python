use std::borrow::Cow;
use std::collections::HashMap;
use icicle_cpu::mem::{Mapping, perm};
use icicle_cpu::{VmExit};
use icicle_vm;
use icicle_vm::linux::LinuxCpu;
use target_lexicon;
use indexmap::IndexMap;
use sleigh_runtime::NamedRegister;

#[allow(dead_code)]
#[derive(Clone)]
enum MemoryProtection {
    NoAccess,
    ReadOnly,
    ReadWrite,
    ExecuteOnly,
    ExecuteRead,
    ExecuteReadWrite,
}

struct Icicle {
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
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

fn reg_find<'a>(i: &'a Icicle, name: &str) -> Result<&'a NamedRegister, String> {
    let sleigh = i.vm.cpu.sleigh();
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(name.to_lowercase().as_str())
                .ok_or(
                    format!("Register not found: {name}")
                )
        }
        Some(r) => Ok(r),
    }
}

impl Icicle {
    #[allow(dead_code)]
    fn get_icount_limit(&mut self) -> u64 {
        self.vm.icount_limit
    }

    #[allow(dead_code)]
    fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    #[allow(dead_code)]
    fn get_icount(&mut self) -> u64 {
        return self.vm.cpu.icount;
    }

    #[allow(dead_code)]
    fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

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
    ) -> Result<Self, String> {
        // Prevent mixing '_' and '-'
        if architecture.split("-").count() != 1 {
            return Err(
                format!("Bad architecture format: {architecture}")
            );
        }

        // TODO: support instantiating this multiple times
        if tracing {
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .init();
        }

        // Setup the CPU state for the target triple
        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-none").as_str()
        );
        if config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(
                format!("Unknown architecture: {architecture}")
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
                format!("VM build error: {e}")
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

    fn mem_map(&mut self, address: u64, size: u64, protection: MemoryProtection) -> Result<(), String> {
        let mapping = Mapping {
            perm: convert_protection(protection),
            value: 0,
        };
        if self.vm.cpu.mem.map_memory_len(address, size, mapping) {
            Ok(())
        } else {
            Err(
                format!("Failed to map memory {address:X}[{size:X}]")
            )
        }
    }

    #[allow(dead_code)]
    fn mem_unmap(&mut self, address: u64, size: u64) -> Result<(), String> {
        if self.vm.cpu.mem.unmap_memory_len(address, size) {
            Ok(())
        } else {
            Err(
                format!("Failed to unmap memory {address:X}[{size:X}]")
            )
        }
    }

    fn mem_protect(&mut self, address: u64, size: usize, protection: MemoryProtection) -> Result<(), String> {
        self.vm.cpu.mem.update_perm(address, size as u64, convert_protection(protection))
            .map_err(|_| {
                format!("Failed to protect memory {address:X}[{size:X}]")
            })?;
        Ok(())
    }

    #[allow(dead_code)]
    fn mem_read(&mut self, address: u64, size: usize) -> Result<Cow<[u8]>, String> {
        // Allocate a buffer
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);

        // Read the memory
        match self.vm.cpu.mem.read_bytes(address, &mut buffer[..], perm::NONE) {
            Ok(_) => Ok(Cow::Owned(buffer)),
            Err(_) => Err(format!("Failed to read memory {address:X}[{size:X}]"))
        }
    }

    fn mem_write(&mut self, address: u64, data: Vec<u8>) -> Result<(), String> {
        let size = data.len();
        match self.vm.cpu.mem.write_bytes(address, &data[..], perm::NONE) {
            Ok(_) => Ok(()),
            Err(_) => Err(format!("Failed to write memory {address:X}[{size:X}]"))
        }
    }

    #[allow(dead_code)]
    fn reg_list(&self) -> IndexMap<String, (u32, u8)> {
        let mut result = IndexMap::new();
        let sleigh = self.vm.cpu.sleigh();
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            result.insert(name.to_string(), (reg.offset, reg.var.size));
        }
        return result;
    }

    #[allow(dead_code)]
    fn reg_offset(&self, name: &str) -> Result<u32, String> {
        Ok(reg_find(self, name)?.offset)
    }

    #[allow(dead_code)]
    fn reg_size(&self, name: &str) -> Result<u8, String> {
        Ok(reg_find(self, name)?.var.size)
    }

    fn reg_read(&mut self, name: &str) -> Result<u64, String> {
        Ok(self.vm.cpu.read_reg(reg_find(self, name)?.var))
    }

    fn reg_write(&mut self, name: &str, value: u64) -> Result<(), String> {
        Ok(self.vm.cpu.write_reg(reg_find(self, name)?.var, value))
    }

    #[allow(dead_code)]
    fn reset(&mut self) {
        self.vm.reset();
    }

    fn run(&mut self) -> VmExit {
        self.vm.run()
    }

    #[allow(dead_code)]
    fn run_until(&mut self, address: u64) -> VmExit {
        let breakpoint_added = self.vm.add_breakpoint(address);
        let status = self.run();
        if breakpoint_added {
            self.vm.remove_breakpoint(address);
        }
        status
    }

    #[allow(dead_code)]
    fn step(&mut self, count: u64) -> VmExit {
        let old_limit = self.vm.icount_limit;
        self.vm.icount_limit = self.vm.cpu.icount.saturating_add(count);
        let status = self.run();
        self.vm.icount_limit = old_limit;
        status
    }

    #[allow(dead_code)]
    fn add_breakpoint(&mut self, address: u64) -> bool {
        self.vm.add_breakpoint(address)
    }

    #[allow(dead_code)]
    fn remove_breakpoint(&mut self, address: u64) -> bool {
        self.vm.remove_breakpoint(address)
    }
}

#[allow(dead_code)]
fn architectures() -> Result<Vec<&'static str>, String> {
    Ok(vec![
        "i686",
        "x86_64",
        "aarch64",
    ])
}

fn nx_start() {
    let mut vm = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    ).unwrap();
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ReadOnly).unwrap();
    // <non-executable memory> inc eax; ret
    vm.mem_write(page, b"\xFF\xC0\xC3".to_vec()).unwrap();
    vm.reg_write("rip", page).unwrap();
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip").unwrap());
}

fn nx_middle() {
    let mut vm = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    ).unwrap();
    let page = 0x10000;
    vm.mem_map(page, 0x2000, MemoryProtection::ExecuteRead).unwrap();
    vm.mem_protect(page + 0x1000, 0x1000, MemoryProtection::ReadOnly).unwrap();
    // inc eax; inc eax; <transition to non-executable region>; ret
    let rip = page + 0x1000 - 2;
    vm.mem_write(rip, b"\xFF\xC0\xFF\xC0\xC3".to_vec()).unwrap();
    vm.reg_write("rip", rip).unwrap();
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip").unwrap());
    println!("rax: {:#x}", vm.reg_read("rax").unwrap());
}

fn inv_start() {
    let mut vm = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    ).unwrap();
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ExecuteRead).unwrap();
    // <invalid>; ret
    vm.mem_write(page, b"\xFF\xFF\xC3".to_vec()).unwrap();
    vm.reg_write("rip", page).unwrap();
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip").unwrap());
    println!("rax: {:#x}", vm.reg_read("rax").unwrap());
}

fn inv_middle() {
    let mut vm = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    ).unwrap();
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ExecuteRead).unwrap();
    // inc eax; <invalid>; ret
    vm.mem_write(page, b"\xFF\xC0\xFF\xFF\xC3".to_vec()).unwrap();
    vm.reg_write("rip", page).unwrap();
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip").unwrap());
    println!("rax: {:#x}", vm.reg_read("rax").unwrap());
}

fn main() {
    println!("=== NX (block start) ===");
    nx_start();
    println!("=== NX (block middle) ===");
    nx_middle();
    println!("=== Invalid instruction (block start) ===");
    inv_start();
    println!("=== Invalid instruction (block middle) ===");
    inv_middle();
}
