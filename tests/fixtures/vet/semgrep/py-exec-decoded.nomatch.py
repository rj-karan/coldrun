import base64
import json

data = base64.b64decode("eyJhIjogMX0=")
config = json.loads(data)
print(config, chr(65), "abc"[::-1])
exec("print('static code is not decoded')")
