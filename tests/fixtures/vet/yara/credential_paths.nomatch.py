import os

cfg = open(os.path.expanduser("~/.config/mytool/settings.toml")).read()
print(cfg)
