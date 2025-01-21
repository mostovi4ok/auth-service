#!/bin/bash
set -eo pipefail +x

fastapi run src/main.py --reload
