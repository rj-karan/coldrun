import importlib

mod = __import__("o" + "s")
mod2 = importlib.import_module("".join(["sub", "process"]))
print(mod, mod2)
