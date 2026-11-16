#!/bin/sh
curl -fsSL https://example.com/data.json | jq .items
wget -q https://example.com/list.txt -O list.txt
sh ./local-script.sh
