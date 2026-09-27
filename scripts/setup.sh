#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
environment_path="${repository_root}/.venv"
required_python="3.12"

cd "${repository_root}"
detected="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "${detected}" != "${required_python}" ]]; then
  echo "Stoá: Python ${required_python} is required; detected ${detected}." >&2
  exit 1
fi

if [[ ! -d "${environment_path}" ]]; then
  python3 -m venv "${environment_path}"
fi

environment_python="${environment_path}/bin/python"
"${environment_python}" -m pip install --disable-pip-version-check --upgrade "pip==26.2.1"
"${environment_python}" -m pip install --disable-pip-version-check -r requirements/dev.txt
"${environment_python}" -m pip install --disable-pip-version-check --editable . --no-deps
echo "Stoa development environment is ready."
