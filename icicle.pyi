from typing import List, Dict, Tuple
from enum import Enum

class MemoryProtection(Enum):
    NoAccess = ...
    ReadOnly = ...
    ReadWrite = ...
    ExecuteOnly = ...
    ExecuteRead = ...
    ExecuteReadWrite = ...

class MemoryErrorCode(Enum):
    Unallocated = ...
    Unmapped = ...
    Uninitialized = ...
    ReadViolation = ...
    WriteViolation = ...
    ExecViolation = ...
    ReadWatch = ...
    WriteWatch = ...
    Unaligned = ...
    OutOfMemory = ...
    SelfModifyingCode = ...
    AddressOverflow = ...
    Unknown = ...

class RunStatus(Enum):
    Running = ...
    InstructionLimit = ...
    Breakpoint = ...
    Interrupted = ...
    Halt = ...
    Killed = ...
    Deadlock = ...
    OutOfMemory = ...
    Unimplemented = ...
    UnhandledException = ...

class ExceptionCode(Enum):
    NoException = ...
    InstructionLimit = ...
    Halt = ...
    Sleep = ...
    Syscall = ...
    CpuStateChanged = ...
    DivideByZero = ...
    ReadUnmapped = ...
    ReadPerm = ...
    ReadUnaligned = ...
    ReadWatch = ...
    ReadUninitialized = ...
    WriteUnmapped = ...
    WritePerm = ...
    WriteWatch = ...
    WriteUnaligned = ...
    ExecViolation = ...
    SelfModifyingCode = ...
    OutOfMemory = ...
    AddressOverflow = ...
    InvalidInstruction = ...
    UnknownInterrupt = ...
    UnknownCpuID = ...
    InvalidOpSize = ...
    InvalidFloatSize = ...
    CodeNotTranslated = ...
    ShadowStackOverflow = ...
    ShadowStackInvalid = ...
    InvalidTarget = ...
    UnimplementedOp = ...
    ExternalAddr = ...
    Environment = ...
    JitError = ...
    InternalError = ...
    UnknownError = ...

class MemoryError(Exception):
    code: MemoryErrorCode

class Icicle:
    def __init__(self, architecture: str, *,
                 jit = True,
                 jit_mem = True,
                 shadow_stack = True,
                 recompilation = True,
                 track_uninitialized = False,
                 optimize_instructions = True,
                 optimize_block = True,
                 tracing = False,
                 ) -> None: ...

    @property
    def exception_code(self) -> ExceptionCode: ...

    @property
    def exception_value(self) -> int: ...

    icount: int

    icount_limit: int

    # TODO: API to get memory information?

    def mem_map(self, address: int, size: int, protection: MemoryProtection): ...

    def mem_unmap(self, address: int, size: int): ...

    def mem_protect(self, address: int, size: int, protection: MemoryProtection): ...

    def mem_read(self, address: int, size: int) -> bytes: ...

    def mem_write(self, address: int, data: bytes) -> None: ...

    def reg_list(self) -> Dict[str, Tuple[int, int]]: ...

    def reg_offset(self, name: str) -> int: ...

    def reg_size(self, name: str) -> int: ...

    def reg_read(self, name: str) -> int: ...

    def reg_write(self, name: str, value: int) -> None: ...

    def reset(self): ...

    def run(self) -> RunStatus: ...

    def run_until(self, address: int) -> RunStatus: ...

    def step(self, count: int) -> RunStatus: ...

    def add_breakpoint(self, address: int) -> bool: ...

    def remove_breakpoint(self, address: int) -> bool: ...

def architectures() -> List[str]: ...
