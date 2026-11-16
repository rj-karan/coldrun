#!/usr/bin/env python3
"""Three third-party imports and nothing else; no manifest."""
import json
import os.path
from collections import Counter

import requests
import yaml
from bs4 import BeautifulSoup

print("imports ok", requests.__name__, yaml.__name__, BeautifulSoup.__name__, json, os.path, Counter)
