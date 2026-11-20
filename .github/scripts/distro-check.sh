#!/bin/sh
# Runs inside a distribution's own container image (see .github/workflows/distros.yml):
# installs that distribution's python3 and bubblewrap, then exercises coldrun's sandbox
# as an ordinary user, the way someone on that distribution would run it.
set -eu

if command -v pacman >/dev/null; then
    pacman -Syu --noconfirm --needed python bubblewrap util-linux curl bash
elif command -v apt-get >/dev/null; then
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
        python3 python3-venv bubblewrap curl ca-certificates passwd
elif command -v dnf >/dev/null; then
    # Rocky 9's python3 is 3.9; coldrun needs 3.10, so take 3.11 where it exists
    # curl itself comes from curl-minimal on Rocky, which conflicts with the full package
    dnf install -y python3 bubblewrap shadow-utils util-linux
    dnf install -y python3.11 || true
elif command -v zypper >/dev/null; then
    zypper -n install python3 bubblewrap curl shadow util-linux
elif command -v apk >/dev/null; then
    apk add --no-cache python3 bubblewrap curl bash
else
    echo "no known package manager" >&2
    exit 1
fi

py=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null &&
        "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        py=$(command -v "$candidate")
        break
    fi
done
[ -n "$py" ] || { echo "no python 3.10 or newer" >&2; exit 1; }

. /etc/os-release
echo "== $PRETTY_NAME, $($py --version), $(bwrap --version)"

if command -v useradd >/dev/null; then useradd -m tester; else adduser -D tester; fi
cp -r /src /home/tester/src
chown -R tester /home/tester/src

su -s /bin/sh tester -c "
    set -eu
    cd /home/tester/src
    $py -m venv /home/tester/venv
    /home/tester/venv/bin/pip install -q . pytest
    /home/tester/venv/bin/coldrun doctor || true
    /home/tester/venv/bin/coldrun run tests/fixtures/sh/hello.sh
    /home/tester/venv/bin/python -m pytest -q -p no:cacheprovider -m sandbox \
        tests/integration/test_bwrap_smoke.py tests/integration/test_bwrap_backend.py
"
