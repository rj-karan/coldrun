#!/bin/sh
echo "aGVsbG8=" | base64 -d
printf '\x41\n'
eval "ls -la"
