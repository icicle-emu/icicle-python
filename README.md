# icicle-python

This project is an easy-to-use Python wrapper around [icicle-emu](https://github.com/icicle-emu/icicle-emu). You can read more about Icicle in the paper: [Icicle: A Re-designed Emulator for Grey-Box Firmware Fuzzing](https://arxiv.org/pdf/2301.13346.pdf).

## Installation

You can install the [latest release](https://github.com/icicle-emu/icicle-python/releases) from [PyPI](https://pypi.org/project/icicle-emu):

```
pip install icicle-emu
```

## Development

_Note_: You need to install [Rust 1.90](https://rustup.rs) or higher to build from source.

### Install uv

```shell
# On Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
# On macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### Build the project

```shell
# Clone the repository with submodules
git clone --recursive https://github.com/icicle-emu/icicle-python
cd icicle-python

# Install dependencies and build
uv sync
uv run maturin develop
```

### Running tests

The `tests` folder contains tests that double as standalone examples. Prefix a function with `test_` to automatically run it:

```shell
uv run pytest -v
```

Alternatively you can `uv run tests/example.py` to run/debug the standalone example.

### Building a wheel

```shell
uv build
```
