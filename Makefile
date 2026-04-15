.PHONY: install install-dev stdio serve test test-cov demo clean

install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev]"

stdio:
	python -m app --transport stdio

serve:
	python -m app --transport http --host 127.0.0.1 --port 8765

test:
	pytest -v

test-cov:
	pytest -v --cov=app --cov-report=term-missing

demo:
	bash scripts/demo.sh

clean:
	rm -rf .pytest_cache .coverage coverage.xml htmlcov dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
