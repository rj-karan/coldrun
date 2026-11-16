#!/bin/bash
# Uses jq and curl without the network.
curl --version | head -1 | cut -d" " -f1
echo '{"answer": 42}' | jq .answer
