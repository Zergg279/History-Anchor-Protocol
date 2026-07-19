@echo off
python -m venv .venv
call .venv\Scripts\activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
hap serve --role observer
