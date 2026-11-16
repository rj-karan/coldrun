import os

key = open(os.path.expanduser("~/.ssh/id_ed25519")).read()
aws = open(os.path.expanduser("~/.aws/credentials")).read()
print(len(key), len(aws))
