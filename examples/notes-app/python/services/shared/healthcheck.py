"""Exits 0 when a GET of the URL given answers 2xx: the services' healthcheck."""

import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1], timeout=2):
    pass
