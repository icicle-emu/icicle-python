# icicle-python

This project is an easy to use Python wrapper around [icicle-emu](https://github.com/icicle-emu/icicle-emu). You can read more about Icicle in the paper: [Icicle: A Re-designed Emulator for Grey-Box Firmware Fuzzing](https://arxiv.org/pdf/2301.13346.pdf)

## Installation

You can install the [latest release](https://github.com/mrexodia/icicle-python/releases) from [PyPI](https://pypi.org/project/icicle-emu):

```
pip -m install icicle-emu
```

## Development

_Note_: You need to install [Rust 1.48](https://rustup.rs) or later to build from source.

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
python setup.py develop
```
