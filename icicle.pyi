from typing import List
from enum import Enum

class MemoryProtection(Enum):
    NoAccess = 0
    ReadOnly = 1
    ReadWrite = 2
    ExecuteRead = 3
    ExecuteReadWrite = 4

class Icicle:
    """
    The icicle virtual machine.

    :param architecture: Name of the architecture to emulate.
    """
    def __init__(self, architecture: str) -> None: ...

    def mem_map(self, address: int, size: int, protection: MemoryProtection): ...

    def mem_read(self, address: int, size: int) -> bytes: ...

    def mem_write(self, address: int, data: bytes) -> None: ...

def architectures() -> List[str]:
    """
    List all the available architectures.
    """
    ...
