try:
    xfail = __import__("pytest").mark.xfail(reason="Known broken")
except ImportError:
    xfail = lambda func: func

from icicle import *

"""
issue: https://github.com/icicle-emu/icicle-emu/issues/64

mchesser:
Yeah, an assumption that the block optimizer makes is that there will be no external modifications to registers within a blocks. This issue can be reproduced with something as simple as:

[4c 89 c9] "MOV RCX, R9"
[49 89 c9] "MOV R9, RCX"
Which optimizes to the following Pcode:

<L0> (entry=0x0):
	instruction(0x0)
	RCX = R9
	instruction(0x3)
Without this assumption, it is essentially impossible to perform any optimization that cross instruction boundaries.

That said there are a couple of ways that this could be made better:

Disable block-level optimizations by default (or remove them completely) -- in general they don't actually help that much for performance and after 802ab0c, most of the optimizations should already be done by Cranelift, which affects full-block execution anyway.
Only apply optimizations to the JIT-blocks, meaning the interpreter (which is what is used for single stepping) executes the unoptimized pcode. The emulator checks some preconditions to ensure that the block will either be executed to completion (or to some known exit points) before entering the JIT.
Warn when "reg_write" is performed inside of a block when block-level optimizations are enabled.
Automatically de-optimize the block if a manual reg-write is performed in it.
Bypass the code-cache and disable optimizations when performing single stepping.
Add more control over the optimization process (e.g. const-prop flags, but not GPRs).
I'm thinking that (1.) is probably the best solution the near term. Currently the main reason for the block-level optimizations is to simplify some static analysis that occurs later in my other work (fuzzing) and make the pcode more "readable".

However, I want to potentially move towards (2.) in the future to allow for more aggressive optimizations in certain cases.
"""
@xfail
def test_blockopt():
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
    test_blockopt()
