#!/usr/bin/env python3
"""Test script to verify that exceptions now include size and data fields."""

import sys
sys.path.insert(0, './python')

from icicle import *

def test_write_exception():
    """Test that write exceptions from CPU include size and data."""
    print("Testing CPU write exception with size and data...")

    # Create a VM
    vm = Icicle("x86_64", jit=False)

    # Map some executable memory for our code
    code_page = 0x10000
    vm.mem_map(code_page, 0x1000, MemoryProtection.ExecuteReadWrite)

    # Map a read-only page that we'll try to write to
    readonly_page = 0x20000
    vm.mem_map(readonly_page, 0x1000, MemoryProtection.ReadOnly)

    # Write some code that tries to write to read-only memory
    # mov rax, 0x20000  (address of read-only page)
    # mov rbx, 0x0102030405060708
    # mov [rax], rbx
    code = bytes.fromhex("48b80000020000000000" + "48bb0807060504030201" + "488918")
    vm.mem_write(code_page, code)

    # Execute the code
    vm.reg_write("rip", code_page)

    status = vm.run()
    print(f"[OK] Execution stopped with status: {status}")
    print(f"  - Exception code: {vm.exception_code}")
    print(f"  - Exception value (address): 0x{vm.exception_value:x}")
    print(f"  - Exception size: {vm.exception_size}")
    print(f"  - Exception data: {vm.exception_data.hex() if vm.exception_data else 'none'}")

    # The exception should be a write permission error
    assert vm.exception_code == ExceptionCode.WritePerm
    assert vm.exception_value == readonly_page
    print("[OK] Write exception captured with size and data!")

def test_read_exception():
    """Test that read exceptions include size but no data."""
    print("Testing CPU read exception with size...")

    # Create a VM
    vm = Icicle("x86_64", jit=False)

    # Map some executable memory for our code
    code_page = 0x10000
    vm.mem_map(code_page, 0x1000, MemoryProtection.ExecuteReadWrite)

    # Write some code that tries to read from unmapped memory
    # mov rax, 0xDEADBEEF
    # mov bx, word [rax]
    code = bytes.fromhex("48B8EFBEADDE00000000" + "668B18")  # mov rax, 0xdeadbeef; mov bx, word [rax]
    vm.mem_write(code_page, code)

    # Execute the code
    vm.reg_write("rip", code_page)

    status = vm.run()
    print(f"[OK] Execution stopped with status: {status}")
    print(f"  - Exception code: {vm.exception_code}")
    print(f"  - Exception value (address): 0x{vm.exception_value:x}")
    print(f"  - Exception size: {vm.exception_size}")
    print(f"  - Exception data: {vm.exception_data.hex() if vm.exception_data else '<empty>'}")

    # The exception should be a read unmapped error
    assert vm.exception_code == ExceptionCode.ReadUnmapped, vm.exception_code
    assert vm.exception_value == 0xDEADBEEF
    assert vm.exception_size == 2  # 16-bit read
    # For read exceptions, data field should be empty (no actual data was read)
    assert len(vm.exception_data) == 0, f"Read exceptions should have no data, but got: {vm.exception_data.hex()}"
    print("[OK] Read exception captured with size but no data!")

def test_execution_exception():
    """Test execution exceptions from the CPU."""
    print("\nTesting CPU execution exception with size...")

    # Create a VM
    vm = Icicle("x86_64", jit=False)

    # Map memory as read-write (not executable)
    page = 0x10000
    vm.mem_map(page, 0x1000, MemoryProtection.ReadWrite)

    # Write some code that tries to write to unmapped memory
    # mov rax, 0xDEADBEEF
    # mov [rax], rbx
    code = bytes.fromhex("48b8efbeadde00000000488918")
    vm.mem_write(page, code)

    # Map the page as executable now
    vm.mem_protect(page, 0x1000, MemoryProtection.ExecuteRead)

    # Execute the code
    vm.reg_write("rip", page)
    vm.reg_write("rbx", 0x4142434445464748)  # Some test data

    status = vm.run()
    print(f"[OK] Execution stopped with status: {status}")
    print(f"  - Exception code: {vm.exception_code}")
    print(f"  - Exception value (address): 0x{vm.exception_value:x}")
    print(f"  - Exception size: {vm.exception_size}")
    print(f"  - Exception data: {vm.exception_data.hex() if vm.exception_data else 'none'}")

    # The exception should be a write to unmapped memory
    assert vm.exception_code == ExceptionCode.WriteUnmapped
    assert vm.exception_value == 0xDEADBEEF
    assert vm.exception_size == 8  # 64-bit write
    # Check that we got the data that was trying to be written
    expected_data = (0x4142434445464748).to_bytes(8, 'little')
    assert vm.exception_data == expected_data, f"Data mismatch: {vm.exception_data.hex()} != {expected_data.hex()}"
    print("[OK] CPU exception data matches!")

def main():
    print("=== Testing Extended Exception Information ===\n")

    test_write_exception()
    test_read_exception()
    test_execution_exception()

    print("\n=== All tests passed! ===")

if __name__ == "__main__":
    main()