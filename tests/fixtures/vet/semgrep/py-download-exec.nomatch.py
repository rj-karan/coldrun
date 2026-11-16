import subprocess

import requests

page = requests.get("https://target.example/login").text
print(len(page))
subprocess.run(["nmap", "-sV", "target.example"])
