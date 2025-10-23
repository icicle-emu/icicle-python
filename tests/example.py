import icicle

def assemble(code: str, addr: int = 0) -> bytes:
    import keystone
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, count = ks.asm(code, addr)
    if encoding is None:
        raise keystone.KsError("no encoding")
    return bytes(encoding)

def disassemble(code: bytes, addr: int = 0, max_count = 1000) -> str:
    import capstone
    result = ""
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    count = 0
    while count < max_count:
        count += 1
        # TODO: fix on invalid instruction
        for address, size, mnemonic, op_str in cs.disasm_lite(code, addr, 1):
            if len(result) > 0:
                result += "\n"
            result += hex(address) + "|"
            result += mnemonic
            if op_str:
                result += " "
                result += op_str
            code = code[size:]
            if len(code) == 0:
                return result
            addr += size
    return result

def test_old():
    buf = assemble("mov eax, ebx\nnop")
    print(disassemble(buf, 0))
    print(assemble("mov eax, ebx").hex())
    print("Hello world!")
    print(dir(icicle))
    print(icicle.MemoryProtection.ReadOnly)
    print(f"Architectures: {icicle.architectures()}")
    vm = icicle.Icicle("x86_64")
    print(vm)

    for name, (offset, size) in vm.reg_list().items():
        value = vm.reg_read(name.lower())
        print(f"{name}[{size}] @ {offset} = {value}")

    addr = 0x10000
    vm.mem_map(addr, 0x1000, icicle.MemoryProtection.NoAccess)
    try:
        vm.mem_protect(addr, 0x2000, icicle.MemoryProtection.ExecuteRead)
    except icicle.MemoryException as x:
        print("MemoryException working!")
        message = x.args[0]
        print(message, x.code)
    except Exception as x:
        print(x, type(x), isinstance(x, icicle.MemoryException))
    vm.mem_protect(addr, 0x1000, icicle.MemoryProtection.ExecuteRead)
    vm.mem_write(addr, b"\x90\x90\x90")
    data = vm.mem_read(addr, 4)
    print(data, type(data))

def test_new():
    print("")
    vm = icicle.Icicle("x86_64", jit=False)
    print(vm)

    addr = 0x10000
    #vm.mem_map(0, 0x1000, icicle.MemoryProtection.ReadWrite)
    vm.mem_map(addr, 0x1000, icicle.MemoryProtection.ExecuteRead)
    code = assemble("""
mov eax, 42
mov qword ptr [rax], 0x5
nop
""", addr)
    print("code:")
    print(disassemble(code, addr))
    vm.mem_write(addr, code)
    data = vm.mem_read(addr, len(code))
    assert data == code

    vm.reg_write("rip", addr)
    status = vm.run_until(addr + len(code))
    print(status)
    if status == icicle.RunStatus.UnhandledException:
        print(f"code: {vm.exception_code}, value: {hex(vm.exception_value)}")
        print(f"rip: {hex(vm.reg_read('rip'))} (OK)")
    else:
        print(f"rax: {hex(vm.reg_read('rax'))}")
        assert False, "Should be unreachable"

def main():
    test_old()
    test_new()

if __name__ == "__main__":
    main()
