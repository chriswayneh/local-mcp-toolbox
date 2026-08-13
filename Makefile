.PHONY: install doctor run test lint format typecheck audit docs-validate package-build sbom compose-validate docker-build docker-doctor

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

docs-validate:
	python scripts/validate_docs.py
	python -m pytest tests/unit/test_demo_assets.py

package-build:
	python -m build

sbom:
	mkdir -p dist
	cyclonedx-py environment --output-file dist/sbom.cdx.json

compose-validate:
	docker compose --profile core -f compose.yaml config
	docker compose --profile docker -f compose.yaml config
	docker compose --profile development -f compose.yaml -f compose.dev.yaml config
	docker compose --profile direct-docker -f compose.yaml -f compose.direct-socket.yaml config

docker-build:
	docker build --tag local-mcp-toolbox:local .

docker-doctor:
	docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m local-mcp-toolbox:local doctor --config /app/config/container.yml
