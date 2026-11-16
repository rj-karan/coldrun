#!/bin/sh
grep -q alias ~/.bashrc && echo "has aliases"
cat "$HOME/.zshrc" | wc -l
