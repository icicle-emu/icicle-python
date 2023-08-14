from pathlib import Path
from shutil import copytree, rmtree
from argparse import ArgumentParser

def main():
    parser = ArgumentParser()
    parser.add_argument("ghidra_src", help="Path to the Ghidra source code")
    args = parser.parse_args()
    ghidra_src = Path(args.ghidra_src)
    if not ghidra_src.is_dir():
        raise FileNotFoundError(f"Not a directory: {ghidra_src}")
    processors = ghidra_src.joinpath("Ghidra", "Processors")
    if not ghidra_src.is_dir():
        raise FileNotFoundError(f"Not found: {processors}")
    target_root = Path.cwd().joinpath("python", "icicle", "Ghidra", "Processors")
    if target_root.exists():
        rmtree(target_root)
    for processor in processors.glob("*"):
        if not processor.is_dir():
            continue
        name = processor.name
        languages = processor.joinpath("data", "languages")
        if not languages.is_dir():
            print(f"Processor skipped: {name}")
            continue
        print(f"Processor: {name}")
        processor_root = target_root.joinpath(name, "data", "languages")
        copytree(languages, processor_root, dirs_exist_ok=True)

if __name__ == "__main__":
    main()