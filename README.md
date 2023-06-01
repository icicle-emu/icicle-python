# icicle-unicorn

This project is an attempt to replace unicorn with a wrapper around [icicle-emu](https://github.com/icicle-emu/icicle-emu).

## Requirements

- [Python 3.7+](https://www.python.org/downloads/)
- [Rust 1.48](https://rustup.rs/)

## Building

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