# icicle-python

This project is an easy to use Python wrapper around [icicle-emu](https://github.com/icicle-emu/icicle-emu). You can read more about Icicle in the paper: [Icicle: A Re-designed Emulator for Grey-Box Firmware Fuzzing](https://arxiv.org/pdf/2301.13346.pdf)

## Requirements

- [Python 3.7+](https://www.python.org/downloads/)
- [Rust 1.48](https://rustup.rs/)

## Building

TODO: talk about the submodule

TODO: clone ghidra and set `GHIDRA_SRC` environment variable

Set up a virtual environment:

```shell
python -m venv venv
# macOS/Linux
source venv/bin/activate
# Windows
venv\Scripts\activate.bat
```

Get the dependencies and build:

```shell
pip install -r requirements.txt
maturin develop
```