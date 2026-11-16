import importlib

mod = importlib.import_module("json")
plugin = __import__("os")
print(mod, plugin)
