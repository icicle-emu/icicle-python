import icicle
import keystone
import capstone

def assemble(code: str, addr: int = 0) -> bytes:
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, count = ks.asm(code, addr)
    if encoding is None:
        raise keystone.KsError("no encoding")
    return bytes(encoding)

def disassemble(code: bytes, addr: int = 0) -> str:
    result = ""
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    while True:
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

def old_test():
    buf = assemble("mov eax, ebx\nnop")
    print(disassemble(buf, 0))
    print(assemble("mov eax, ebx").hex())
    print("Hello world!")
    print(dir(icicle))
    print(icicle.MemoryProtection.ReadOnly)
    print(f"Architectures: {icicle.architectures()}")
    vm = icicle.Icicle("x86_64")

    for name, (offset, size) in vm.reg_list().items():
        value = vm.reg_read(name.lower())
        print(f"{name}[{size}] @ {offset} = {value}")

    addr = 0x10000
    vm.mem_map(addr, 0x1000, icicle.MemoryProtection.NoAccess)
    try:
        vm.mem_protect(addr, 0x2000, icicle.MemoryProtection.ExecuteRead)
    except icicle.MemoryError as x:
        message = x.args[0]
        print(message, x.code)
    except Exception as x:
        print(x, type(x), isinstance(x, icicle.MemoryError))
    vm.mem_protect(addr, 0x1000, icicle.MemoryProtection.ExecuteRead)
    vm.mem_write(addr, b"\x90\x90\x90")
    data = vm.mem_read(addr, 4)
    print(data, type(data))

    print(vm)

def main():
    vm = icicle.Icicle("x86_64", jit=True)
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
        print(f"rip: {hex(vm.reg_read('rip'))}")
    else:
        print(f"rax: {hex(vm.reg_read('rax'))}")

if __name__ == "__main__":
    main()
