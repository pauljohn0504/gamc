#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -e .venv/bin/python ]; then python3 -m venv .venv; fi
.venv/bin/python -m pip install -r requirements.txt
echo 'Open http://127.0.0.1:8000'
.venv/bin/python app.py
