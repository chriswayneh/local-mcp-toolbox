.PHONY: install doctor run test lint format typecheck audit compose-validate docker-build docker-doctor

install:
	python -m pip install -e ".[dev,docker]"

doctor:
	local-mcp-toolbox doctor --config config/restricted.yml

run:
	local-mcp-toolbox serve --config config/restricted.yml

test:
	python -m pytest

lint:
	python -m ruff format --check .
	python -m ruff check .

format:
	python -m ruff format .

typecheck:
	python -m mypy src

audit:
	python -m bandit -q -r src
	python -m pip_audit

compose-validate:
	docker compose --profile core -f compose.yaml config
	docker compose --profile docker -f compose.yaml config
	docker compose --profile development -f compose.yaml -f compose.dev.yaml config
	docker compose --profile direct-docker -f compose.yaml -f compose.direct-socket.yaml config

docker-build:
	docker build --tag local-mcp-toolbox:local .

docker-doctor:
	docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m local-mcp-toolbox:local doctor --config /app/config/container.yml
