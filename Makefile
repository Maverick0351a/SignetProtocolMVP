SHELL := /bin/bash

.PHONY: init dev test format lint precommit docker-build docker-run keys

init:
	python3 -m venv .venv && source .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt -r requirements-dev.txt && pre-commit install

dev:
	PYTHONPATH=./src uvicorn signet_api.main:app --reload --port 8000

test:
	PYTHONPATH=./src pytest -q

format:
	ruff format src tests

lint:
	ruff check src tests

precommit:
	pre-commit run --all-files

docker-build:
	docker build -t signet-mvp:latest .

docker-run:
	docker compose up --build

keys:
	PYTHONPATH=./src python -m signet_cli gen-keys --out-dir ./keys && PYTHONPATH=./src python -m signet_cli gen-hmac --out ./keys/ingress_hmac.json
