import icicle

def main():
    print("Hello world!")
    print(dir(icicle))
    print(icicle.MemoryProtection.ReadOnly)
    print(f"Architectures: {icicle.architectures()}")
    vm = icicle.Icicle("i686")

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

if __name__ == "__main__":
    main()
