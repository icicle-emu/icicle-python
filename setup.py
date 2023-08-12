#!/usr/bin/env python

import sys
from os import getenv
from shutil import which
from setuptools import find_packages, setup
from setuptools_rust import RustExtension

if __name__ == "__main__":
    if "sdist" not in sys.argv and which("cargo") is None:
        raise FileNotFoundError(f"Rust not found, visit https://rustup.rs for installation instructions")

    ref_name = getenv("GITHUB_REF_NAME")
    if ref_name:
        from pkg_resources import parse_version
        try:
            parse_version(ref_name)
            print(f"injecting version = {ref_name} into setup.cfg")
            with open("setup.cfg", "r") as f:
                lines = f.readlines()
            with open("setup.cfg", "w") as f:
                for line in lines:
                    if line.startswith("version = "):
                        line = f"version = {ref_name}\n"
                    f.write(line)
        except Exception:
            pass

    setup(
        rust_extensions=[RustExtension("icicle.icicle")],
    )
