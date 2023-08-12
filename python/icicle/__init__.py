from .icicle import *

class MemoryError(Exception):
    def __init__(self, message, code):
        super().__init__(message)
        self.code = code
    def __str__(self):
        return f"{super().__str__()}: {self.code}"

def __ghidra_init():
    import os
    for path in __path__ + [os.getenv("GHIDRA_SRC", ".")]:
        processors_dir = os.path.join(path, "Ghidra/Processors")
        if os.path.isdir(processors_dir):
            os.putenv("GHIDRA_SRC", path)
            os.environ["GHIDRA_SRC"] = path
            return
    raise FileNotFoundError("Ghidra processor definitions not found")

__ghidra_init()
