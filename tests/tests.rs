use icicle::*;
use pyo3::PyResult;

fn nx_start() -> PyResult<()> {
    let mut vm: Icicle = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    )?;
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ReadOnly)?;
    // <non-executable memory> inc eax; ret
    vm.mem_write(page, b"\xFF\xC0\xC3".to_vec())?;
    vm.reg_write("rip", page)?;
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip")?);

    Ok(())
}

fn nx_middle() -> PyResult<()> {
    let mut vm: Icicle = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    )?;
    let page = 0x10000;
    vm.mem_map(page, 0x2000, MemoryProtection::ExecuteRead)?;
    vm.mem_protect(page + 0x1000, 0x1000, MemoryProtection::ReadOnly)?;
    // inc eax; inc eax; <transition to non-executable region>; ret
    let rip = page + 0x1000 - 2;
    vm.mem_write(rip, b"\xFF\xC0\xFF\xC0\xC3".to_vec())?;
    vm.reg_write("rip", rip)?;
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip")?);
    println!("rax: {:#x}", vm.reg_read("rax")?);

    Ok(())
}

fn inv_start() -> PyResult<()> {
    let mut vm: Icicle = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    )?;
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ExecuteRead)?;
    // <invalid>; ret
    vm.mem_write(page, b"\xFF\xFF\xC3".to_vec())?;
    vm.reg_write("rip", page)?;
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip")?);
    println!("rax: {:#x}", vm.reg_read("rax")?);

    Ok(())
}

fn inv_middle() -> PyResult<()> {
    let mut vm: Icicle = Icicle::new(
        "x86_64".to_string(),
        false,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    )?;
    let page = 0x10000;
    vm.mem_map(page, 0x1000, MemoryProtection::ExecuteRead)?;
    // inc eax; <invalid>; ret
    vm.mem_write(page, b"\xFF\xC0\xFF\xFF\xC3".to_vec())?;
    vm.reg_write("rip", page)?;
    let status = vm.run();
    println!("status: {:?}", status);
    println!("rip: {:#x}", vm.reg_read("rip")?);
    println!("rax: {:#x}", vm.reg_read("rax")?);

    Ok(())
}

fn block_optimization() -> PyResult<()> {
    let mut vm: Icicle = Icicle::new(
        "x86_64".to_string(), // architecture
        true,                 // jit
        true,                 // jit_mem
        true,                 // shadow_stack
        true,                 // recompilation
        false,                // track_uninitialized
        true,                 // optimize_instructions
        true,                 // optimize_block
        false,                // tracing
    )?;

    // Memory setup
    let addr: u64 = 0x140001A73;
    let heap: u64 = 0x71000;
    vm.mem_map(heap, 0x1000, MemoryProtection::ReadWrite)?;
    vm.mem_write(heap + 4, b"\x37\x13\x00\x00".to_vec())?;
    vm.mem_map(addr & !0xFFF, 0x1000, MemoryProtection::ExecuteRead)?;
    vm.mem_write(addr, b"\x41\xc1\xea\x07\x41\x83\xe2\x1f\x74\x08\x44\x89\xd0\x48\x89\x54\xc6\x08\x49\x83\xc1\x04\x4c\x89\x0e\x4c\x89\xc9\x44\x8b\x11\x44\x89\xd0\xf7\xd0\x49\x89\xc9\xa8\x03\x0f\x84\x88\xf6\xff\xff\xeb\x4c".to_vec())?;

    // Register setup
    vm.reg_write("r9", heap)?;
    vm.reg_write("r10", 0x13)?;
    vm.reg_write("rip", addr)?;
    vm.reg_write("rsi", heap + 0x100)?;

    // Step through instructions
    for i in 0..11 {
        let rip = vm.reg_read("rip")?;
        let rcx = vm.reg_read("rcx")?;
        let r9 = vm.reg_read("r9")?;

        println!("[{}] RIP: {:#x}, RCX: {:#x}, R9: {:#x}", i, rip, rcx, r9);

        if rip == 0x140001A8F {
            vm.reg_write("r9", 0x13370900)?;
        }

        vm.step(1);

        if rip == 0x140001A9A {
            if rcx != r9 {
                println!("[BUG] expected rcx({:#x}) == r9({:#x})", rcx, r9);
            } else {
                println!("Everything works!");
            }
        }
    }

    Ok(())
}

fn main() {
    #![allow(unused_must_use)]
    println!("=== NX (block start) ===");
    nx_start();
    println!("=== NX (block middle) ===");
    nx_middle();
    println!("=== Invalid instruction (block start) ===");
    inv_start();
    println!("=== Invalid instruction (block middle) ===");
    inv_middle();
    println!("=== Block optimization bug ===");
    block_optimization();
}