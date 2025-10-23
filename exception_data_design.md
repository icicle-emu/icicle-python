# Exception Data Enhancement Design

## Overview

This document describes the design and implementation of enhanced exception information in icicle-python, which extends memory access exceptions to include the size of the access and the data being written.

## Motivation

Previously, when a memory access violation occurred during emulation, the exception only provided:
- The type of violation (read/write/execute permission, unmapped memory, etc.)
- The memory address where the violation occurred

This limited information made debugging difficult because users couldn't determine:
- How large the access was (1 byte? 8 bytes? 16 bytes?)
- What data was being written (for write violations)

These details are crucial for understanding what the emulated code was attempting to do when it failed.

## Design Goals

1. **Capture access size**: Record the number of bytes involved in the memory operation
2. **Capture write data**: For write operations, preserve the actual bytes being written
3. **Maintain simplicity**: Keep the API changes minimal and intuitive
4. **Preserve performance**: Avoid overhead for the normal (non-exceptional) execution path

## Implementation Strategy

### Core Data Structure Changes

The implementation required changes at multiple layers, from the core Rust emulator up through the Python bindings.

#### 1. Exception Structure (Rust Core)

**File**: `icicle-emu/icicle-cpu/src/cpu.rs`

The `Exception` struct was extended with two new fields:
```rust
pub struct Exception {
    pub code: u32,
    pub value: u64,        // Already existed: the address
    pub size: u32,         // NEW: size of the access
    pub data: [u8; 16],    // NEW: up to 16 bytes of data
}
```

Design decisions:
- **Size as u32**: Memory accesses are typically 1-16 bytes, u32 provides plenty of range
- **Data as [u8; 16]**: Fixed-size array avoids heap allocation while supporting common cases (up to 128-bit SIMD operations)
- **Byte array over u64**: Preserves exact byte representation without endianness confusion

#### 2. Memory Operation Handlers

**File**: `icicle-emu/icicle-cpu/src/cpu.rs`

The `UncheckedExecutor` implementation's memory operations were updated:

```rust
// For read operations - capture size only
fn load_mem<const N: usize>(...) {
    if let Err(err) = self.cpu.mem.read::<N>(...) {
        self.cpu.exception = Exception::new_with_size(
            ExceptionCode::from_load_error(err),
            addr,
            N as u32  // Capture the size
        );
    }
}

// For write operations - capture size and data
fn store_mem<const N: usize>(..., value: [u8; N]) {
    if let Err(err) = self.cpu.mem.write(...) {
        self.cpu.exception = Exception::new_with_data(
            ExceptionCode::from_store_error(err),
            addr,
            value  // Capture the actual bytes
        );
    }
}
```

The generic const parameter `N` provides the size at compile time, which we capture in the exception.

### Python Binding Layer

#### 3. Python Bindings (Rust)

**File**: `src/lib.rs`

Added getters to expose the new fields to Python:
```rust
#[getter]
pub fn get_exception_size(&self) -> u32 {
    self.vm.cpu.exception.size
}

#[getter]
pub fn get_exception_data(&self) -> Vec<u8> {
    let size = self.vm.cpu.exception.size as usize;
    if size == 0 {
        Vec::new()
    } else {
        self.vm.cpu.exception.data[..size.min(16)].to_vec()
    }
}
```

The data getter returns only the valid bytes (up to size), not the entire 16-byte buffer.

#### 4. Exception Propagation

**File**: `src/lib.rs`

Updated `raise_MemoryException` to include the new fields:
```rust
fn raise_MemoryException(message: String, e: MemError, size: u32, data: &[u8]) -> PyErr {
    Python::with_gil(|py| {
        let data_bytes = pyo3::types::PyBytes::new(py, data);
        let args = (message, MemoryExceptionCode::from(e), size, data_bytes);
        // ... create exception
    })
}
```

### Python Interface

#### 5. Python Exception Class

**File**: `python/icicle/__init__.py`

Extended the `MemoryException` class:
```python
class MemoryException(Exception):
    def __init__(self, message: str, code: MemoryExceptionCode,
                 size: int = 0, data: bytes = b""):
        super().__init__(message)
        self.code = code
        self.size = size
        self.data = data
```

#### 6. Property Declarations

Added properties to the `Icicle` class interface:
```python
@property
def exception_size(self) -> int: ...

@property
def exception_data(self) -> bytes: ...
```

## Data Flow

When a memory exception occurs:

1. **CPU Execution**: The CPU attempts a memory operation through `load_mem` or `store_mem`
2. **Exception Creation**: If the operation fails, an `Exception` struct is created with:
   - The error code (type of violation)
   - The address (already existed)
   - The size (from the template parameter `N`)
   - The data (for writes only)
3. **Python Access**: Python code can access these fields via:
   - `vm.exception_code` - the type of exception
   - `vm.exception_value` - the address
   - `vm.exception_size` - the size of access
   - `vm.exception_data` - the bytes being written (empty for reads)

## Use Cases

This enhancement enables better debugging and analysis:

1. **Security Analysis**: Understand buffer overflow attempts by seeing exactly what data was being written
2. **Debugging**: Quickly identify whether a crash was from a byte, word, or larger access
3. **Forensics**: Preserve the exact data that failed to write for later analysis
4. **Testing**: Verify that code is attempting to write expected values

## Example Usage

```python
from icicle import *

vm = Icicle("x86_64")
# ... setup and run code that causes exception ...

if vm.exception_code == ExceptionCode.WritePerm:
    print(f"Attempted to write {vm.exception_size} bytes to {hex(vm.exception_value)}")
    print(f"Data: {vm.exception_data.hex()}")
```

## Performance Considerations

- **Zero overhead for success path**: The new fields are only populated when an exception occurs
- **Fixed-size storage**: Using `[u8; 16]` avoids heap allocation
- **Const generics**: The size is known at compile time through Rust's const generics

## Future Enhancements

Potential improvements for future versions:
- Support for larger data captures (>16 bytes) if needed for vector operations
- Additional context like instruction pointer at time of exception
- Register state snapshot at exception time