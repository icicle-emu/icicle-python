#![allow(special_module_name)]
mod lib;

use lib::*;
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
}
