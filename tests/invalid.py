"""
Scenarios:
- Non-executable memory being executed
  - What should happen when the memory doesn't exist at all?
- Invalid instruction at the start of the block
- Invalid instruction in the middle of a block
- IP alignment error (non-x86)
"""

from icicle import *

def nx():
    vm = Icicle("x86_64", jit=False)
    page = 0x10000
    vm.mem_map(page, 0x1000, MemoryProtection.ReadOnly)
    vm.mem_write(page, b"\x90\xC3")
    vm.reg_write("rip", page)
    status = vm.run()
    print(status)
    print(vm.exception_code, hex(vm.exception_value))
    # We expect an execution violation at rip
    assert vm.exception_code == ExceptionCode.ExecViolation
    assert vm.exception_value == page

def inv_start():
    vm = Icicle("x86_64", jit=False)
    page = 0x10000
    vm.mem_map(page, 0x1000, MemoryProtection.ExecuteRead)
    vm.mem_write(page, b"\xFF\xFF\x90")
    vm.reg_write("rip", page)
    status = vm.run()
    print(status)
    print(vm.exception_code, hex(vm.exception_value))
    # We expect an invalid instruction at rip
    assert vm.exception_code == ExceptionCode.InvalidInstruction
    assert vm.exception_value == page

def inv_middle():
    vm = Icicle("x86_64", jit=False)
    page = 0x10000
    vm.mem_map(page, 0x1000, MemoryProtection.ExecuteRead)
    vm.mem_write(page, b"\x90\x90\xFF\xFF\x90")
    vm.reg_write("rip", page)
    status = vm.run()
    print(status)
    print(vm.exception_code, hex(vm.exception_value))
    # We expect an invalid instruction at rip+2
    assert vm.exception_code == ExceptionCode.InvalidInstruction
    assert vm.exception_value == page + 2

def main():
    print("=== NX ===")
    nx()
    print("=== Invalid instruction (block start) ===")
    inv_start()
    print("=== Invalid instruction (block middle) ===")
    inv_middle()
    print("\nSUCCESS")

if __name__ == "__main__":
    main()
