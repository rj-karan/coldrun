#!/bin/sh
ls "$HOME/.ssh" 2>/dev/null && exit 1
test -e /home && exit 2
echo "home hidden"
