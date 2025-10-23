from icicle import *

def hlt():
    vm = Icicle("x86_64", jit=False, tracing=True)
    page = 0x10000
    vm.mem_map(page, 0x1000, MemoryProtection.ExecuteRead)
    vm.mem_write(page, b"\xF4\xEB\xFE")
    vm.reg_write("rip", page)
    status = vm.step(1000)
    print(status, vm.exception_code)
    print(hex(vm.reg_read("rip")))

def main():
    hlt()

if __name__ == "__main__":
    main()