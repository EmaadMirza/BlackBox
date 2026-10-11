PYTHON ?= .venv/bin/python
PYTEST ?= .venv/bin/pytest
RUFF ?= .venv/bin/ruff
BLACKBOX ?= .venv/bin/blackbox
BUNDLE ?= artifacts/bundle.json
PINNED_KEYS ?= artifacts/pinned-keys.json
DEMO_OUTPUT ?= artifacts

.PHONY: up down test gates attack bench lint verify demo-bundle
up:
	docker compose up --build -d
	docker compose -f docker-compose.provider.yml up --build -d

down:
	docker compose -f docker-compose.provider.yml down
	docker compose down

test:
	$(PYTEST) -q

gates:
	$(PYTEST) -q tests/gates

attack:
	$(PYTHON) -c 'from tools.attack_suite.tamper_battery import main; main()'

bench:
	$(PYTHON) -c 'from bench.locustfile import main; main()'

lint:
	$(RUFF) check .
	$(RUFF) format --check .

verify:
	$(BLACKBOX) verify "$(BUNDLE)" --pinned-keys "$(PINNED_KEYS)"

demo-bundle:
	$(PYTHON) -m tools.demo_bundle --output "$(DEMO_OUTPUT)"
