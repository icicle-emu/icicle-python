from icicle import *

def main():
    emu = Icicle("x86_64", jit=True, optimize_block=True, tracing=True)

    instructions = bytes.fromhex("41 C1 EA 07 41 83 E2 1F 74 08 44 89 D0 48 89 54 C6 08 49 83 C1 04 4C 89 0E 4C 89 C9 44 8B 11 44 89 D0 F7 D0 49 89 C9 A8 03 0F 84 88 F6 FF FF EB 4C".replace(" ", ""))

    addr = 0x140001A73
    heap = 0x71000
    emu.mem_map(heap, 0x1000, MemoryProtection.ReadWrite)
    emu.mem_write(heap + 4, 0x1337.to_bytes(4, "little"))
    emu.mem_map(addr & ~0xFFF, 0x1000, MemoryProtection.ExecuteRead)
    emu.mem_write(addr, instructions)
    emu.reg_write("r9", heap)
    emu.reg_write("r10", 0x13)
    emu.reg_write("rip", addr)
    emu.reg_write("rsi", heap + 0x100)

    for i in range(11):
        rip = emu.reg_read("rip")
        rcx = emu.reg_read("rcx")
        r9 = emu.reg_read("r9")
        print(f"[{i}] RIP: {hex(rip)}, RCX: {hex(rcx)}, R9: {hex(r9)}")

        if rip == 0x140001A8F:
            emu.reg_write("r9", 0x13370900)

        emu.step(1)

        if rip == 0x140001A9A:
            assert rcx == r9, f"expected rcx({hex(rcx)}) == r9({hex(r9)})"

    print("Everything works!")

if __name__ == "__main__":
    main()