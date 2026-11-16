import base64
import zlib

payload = "cHJpbnQoJ2hlbGxvJyk="
exec(base64.b64decode(payload))
eval(compile(zlib.decompress(b"x\x9c"), "<s>", "exec"))
exec("".join(chr(c) for c in [112, 114, 105, 110, 116]))
