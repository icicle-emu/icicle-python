# https://github.com/icicle-emu/icicle-python/issues/32
from icicle import Icicle, MemoryProtection, RunStatus, ExceptionCode

def test_memhook():
    data = bytes.fromhex(
        "A1 FF FF 01 00"        # mov     eax, [0x1FFFF]
        "B8 02 00 00 00"        # mov     eax, 2
        "66 A3 A0 B3 01 10"     # mov     [0x1001B3A0], ax
    )

    ice = Icicle("i686")
    ice.mem_map(0, 0x100, MemoryProtection.ExecuteOnly)
    ice.mem_write(0, data)
    status = ice.step(1)
    assert status == RunStatus.UnhandledException
    assert ice.exception_code == ExceptionCode.ReadUnmapped
    assert ice.reg_read("eip") == 0

    ice.mem_map(0x10000, 0x20000, MemoryProtection.ExecuteOnly)
    status = ice.step(1)
    assert status == RunStatus.UnhandledException
    assert ice.exception_code == ExceptionCode.ReadPerm
    assert ice.reg_read("eip") == 0

    ice.mem_protect(0x1FFFF, 4, MemoryProtection.ExecuteReadWrite)
    status = ice.step(1)
    assert status == RunStatus.InstructionLimit

    assert ice.reg_read("eip") == 5
    assert ice.reg_read("eax") == 0

    print("SUCCESS")

if __name__ == "__main__":
    test_memhook()