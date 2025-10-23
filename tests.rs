#![allow(unused)]

use icicle::*;
use pyo3::PyResult;
use std::process::exit;

// NOTE: https://github.com/rust-lang/rust-analyzer/issues/18752
#[test]
fn example() -> PyResult<()> {
    Err(pyo3::exceptions::PyException::new_err("test"))
}

fn new_i686() -> PyResult<()> {
    let mut vm = Icicle::new("i686".to_string(), true, true, false, true, false, true, false, false)?;
    assert_eq!(vm.get_architecture(), "i686");
    Ok(())
}

fn new_vm(jit: bool) -> PyResult<Icicle> {
    Icicle::new(
        "x86_64".to_string(),
        jit,
        true,
        false,
        true,
        false,
        true,
        false,
        false,
    )
}

fn new_trace_vm(jit: bool) -> PyResult<Icicle> {
    Icicle::new(
        "x86_64".to_string(),
        jit,
        true,
        false,
        true,
        false,
        true,
        false,
        true,
    )
}

fn nx_start() -> PyResult<()> {
    let mut vm = new_vm(false)?;
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
    let mut vm = new_vm(false)?;
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
    let mut vm = new_vm(false)?;
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
    let mut vm = new_vm(false)?;
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
        "x86_64".to_string(),
        true,
        true,
        true,
        true,
        false,
        true,
        true,
        false,
    )?;

    // Memory setup
    let addr: u64 = 0x140001A73;
    let heap: u64 = 0x71000;
    vm.mem_map(heap, 0x1000, MemoryProtection::ReadWrite)?;
    vm.mem_write(heap + 4, b"\x37\x13\x00\x00".to_vec())?;
    vm.mem_map(addr & !0xFFF, 0x1000, MemoryProtection::ExecuteRead)?;
    vm.mem_write(addr, b"\x41\xc1\xea\x07\x41\x83\xe2\x1f\x74\x08\x44\x89\xd0\x48\x89\x54\xc6\x08\x49\x83\xc1\x04\x4c\x89\x0e\x4c\x89\xc9\x44\x8b\x11\x44\x89\xd0\xf7\xd0\x49\x89\xc9\xa8\x03\x0f\x84\x88\xf6\xff\xff\xeb\x4c\xcc".to_vec())?;

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

fn rewind() -> PyResult<()> {
    let mut vm = new_vm(true)?;

    vm.mem_map(0x100, 0x20, MemoryProtection::ExecuteRead)?;
    vm.mem_map(0x200, 0x20, MemoryProtection::ReadOnly)?;

    vm.mem_write(0x100, b"\x55\xCC".to_vec())?; // push rbp
    vm.reg_write("rbp", 0xF00)?;
    vm.reg_write("rsp", 0x210)?;
    vm.reg_write("rip", 0x100)?;
    let status = vm.step(1);
    println!("run status      : {:?}", status);
    println!("exception code  : {:?}", vm.get_exception_code());
    println!("exception value : {:#x}", vm.get_exception_value());
    println!("stack pointer   : {:#x}", vm.reg_read("rsp")?);

    Ok(())
}

fn execute_uninitialized() -> PyResult<()> {
    let mut vm = Icicle::new(
        "x86_64".to_string(),
        true,
        true,
        false,
        true,
        true, // NOTE: setting this to true is not properly supported
        true,
        false,
        false,
    )?;

    // \x48\x8d\x05\x01\x00\x00\x00\x90\x8a\x18\x90

    vm.mem_map(0x100, 0x20, MemoryProtection::ExecuteOnly)?;
    vm.mem_write(0x100, b"\x90\xFF\xC0".to_vec())?; // inc eax
    vm.reg_write("rip", 0x100)?;
    {
        println!("[pre1] icount: {}", vm.get_icount());
        let status = vm.step(2);
        // NOTE: the real reason is that INIT is not set
        println!("run status      : {:?}", status);
        println!("exception code  : {:?}", vm.get_exception_code());
        println!("exception value : {:#x}", vm.get_exception_value());
        println!("rax             : {:#x}", vm.reg_read("rax")?);
    }

    {
        println!("[pre2] icount: {}", vm.get_icount());
        let status = vm.step(1);
        // NOTE: the real reason is that INIT is not set
        println!("run status      : {:?}", status);
        println!("exception code  : {:?}", vm.get_exception_code());
        println!("exception value : {:#x}", vm.get_exception_value());
        println!("rax             : {:#x}", vm.reg_read("rax")?);
        println!("[post] icount: {}", vm.get_icount());
    }

    // TODO: status is now UnhandledException, should be InstructionLimit
    // on the next stpe it should be UnhandledException -> ExecViolation

    Ok(())
}

fn execute_only() -> PyResult<()> {
    let mut vm = new_vm(false)?;

    vm.mem_map(0x100, 0x20, MemoryProtection::ExecuteOnly)?;
    /*
    0x100: lea rax, [rip]
    0x107: nop
    0x108: mov bl, byte ptr [rax]
    0x10A: int3
    */
    vm.mem_write(
        0x100,
        b"\x48\x8d\x05\x00\x00\x00\x00\x90\x8a\x18\xCC".to_vec(),
    )?; // nop
    vm.reg_write("rip", 0x100)?;
    vm.step(2);
    let status = vm.step(1);
    // NOTE: the real reason is that INIT is not set
    println!("run status      : {:?}", status);
    println!("exception code  : {:?}", vm.get_exception_code());
    println!("exception value : {:#x}", vm.get_exception_value());
    println!("bl: {:#x}", vm.reg_read("bl")?);
    println!("rip: {:#x}", vm.reg_read("rip")?);

    Ok(())
}

fn self_modifying() -> PyResult<()> {
    // TODO: add a self-modifying code check (where the previously-executed code is written to)

    Ok(())
}

fn step_modify_rip() -> PyResult<()> {
    let mut vm = new_vm(false)?;
    vm.mem_map(0x100, 0x20, MemoryProtection::ExecuteRead)?;

    // 0x100:  48 01 d8                add    rax,rbx
    // 0x103:  48 83 e9 05             sub    rcx,0x5
    // 0x107:  48 89 d9                mov    rcx,rbx
    // 0x10a:  90                      nop
    // 0x10b:  90                      nop
    vm.mem_write(
        0x100,
        b"\x48\x01\xD8\x48\x83\xE9\x05\x48\x89\xD9\x90\x90\xCC".to_vec(),
    )?;

    vm.reg_write("rax", 0xF00)?;
    vm.reg_write("rbx", 0x210)?;
    vm.reg_write("rip", 0x100)?;

    println!("starting run at {:#x}", vm.reg_read("rip")?);
    let mut status = vm.step(1);

    println!(
        "ending run at {:#x} (status: {:?})",
        vm.reg_read("rip")?,
        status
    );
    vm.reg_write("rip", 0x100)?;
    //vm.write_pc(0x100);
    //println!("pc: {:#x}", vm.read_pc());
    println!("rip rewritten {:#x}", vm.reg_read("rip")?);
    status = vm.step(1);
    println!(
        "ending run at {:#x} (status: {:?})",
        vm.reg_read("rip")?,
        status
    );

    Ok(())
}

fn eflags_reconstruction() -> PyResult<()> {
    let mut vm = new_vm(false)?;
    vm.mem_map(0x100, 0x20, MemoryProtection::ExecuteRead)?;

    vm.mem_write(0x100, b"\x48\x01\xD8\xCC".to_vec())?;
    vm.reg_write("rax", 0x7FFFFFFFFFFFFFFF)?;
    vm.reg_write("rbx", 0x1)?;

    let of_mask = (1 << 11) as u64;

    {
        let eflags = vm.reg_read("eflags")?;
        let of = vm.reg_read("OF")?;
        let of_set = (eflags & of_mask) == of_mask;
        println!("[pre] eflags: {:#x}, OF: {:#x} == {}", eflags, of, of_set);
    }

    vm.set_pc(0x100);
    let status = vm.step(1);
    println!("run status: {:?}", status);

    {
        let eflags = vm.reg_read("eflags")?;
        let rflags = vm.reg_read("rflags")?;
        let of = vm.reg_read("OF")?;
        let of_set = (eflags & of_mask) == of_mask;
        println!(
            "[post] eflags: {:#x} == {:#x}, OF: {:#x} == {}",
            eflags, rflags, of, of_set
        );
    }

    {
        vm.reg_write("OF", 0)?;
        let eflags = vm.reg_read("eflags")?;
        let of = vm.reg_read("OF")?;
        let of_set = (eflags >> 11) & 1;
        println!("[OF=0] eflags: {:#x}, OF: {:#x} == {}", eflags, of, of_set);
    }

    {
        let mut eflags = vm.reg_read("eflags")?;
        eflags |= of_mask;
        vm.reg_write("rflags", eflags)?;
        let of = vm.reg_read("OF")?;
        let of_set = (eflags >> 11) & 1;
        println!(
            "[rflags|={:#x}] eflags: {:#x}, OF: {:#x} == {}",
            of_mask, eflags, of, of_set
        );
    }

    Ok(())
}

fn main() {
    // Make sure the GHIDRA_SRC environment variable is valid
    match std::env::var("GHIDRA_SRC") {
        Ok(ghidra_src) => {
            // Make sure the directory $GHIDRA_SRC/Ghidra/Processors exists
            if !std::path::Path::new(&ghidra_src)
                .join("Ghidra")
                .join("Processors")
                .exists()
            {
                println!("GHIDRA_SRC environment variable invalid!");
                exit(1);
            }
            println!("GHIDRA_SRC: {}", ghidra_src);
        }
        Err(_) => {
            println!("GHIDRA_SRC environment variable not set!");
            exit(1);
        }
    }

    let tests: Vec<(&str, fn() -> PyResult<()>)> = vec![
        ("New i686", new_i686),
        ("NX (block start)", nx_start),
        ("NX (block middle)", nx_middle),
        ("Invalid instruction (block start)", inv_start),
        ("Invalid instruction (block middle)", inv_middle),
        ("Block optimization bug", block_optimization),
        ("Rewind", rewind),
        ("Execute only", execute_only),
        ("Execute uninitialized", execute_uninitialized),
        ("Step modify rip", step_modify_rip),
        ("EFlags reconstruction", eflags_reconstruction),
    ];

    let mut success = 0;
    for (name, f) in tests.iter() {
        println!("=== {} ===", name);
        match f() {
            Ok(_) => {
                success += 1;
                println!("[OK]");
            }
            Err(e) => {
                println!("[ERROR] {}", e);
            }
        }
    }

    println!("{}/{} tests passed", success, tests.len());
    exit(if success == tests.len() { 0 } else { 1 });
}
