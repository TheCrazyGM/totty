.PHONY: check clean clean-build clean-pyc dev-setup dist docs format generate-versions git install lint release tag test-dist

clean: clean-build clean-pyc

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr *.egg-info
	rm -fr __pycache__/ .eggs/ .cache/ .tox/

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

lint:
	uv run ruff check src

format:
	uv run ruff check --select I --fix src
	uv run ruff format src

build: generate-versions
	uv build

install: build
	uv pip install -e .

git:
	git push --all
	git push --tags

check:
	uv pip check

dev-setup:
	uv sync --dev

dist: generate-versions
	uv build
	uvx uv-publish@latest --repo pypi

tag:
	@VERSION=$$(grep -m1 '^version[[:space:]]*=' pyproject.toml | cut -d '"' -f2) && \
	echo "Creating git tag v$$VERSION" && \
	git tag -a "v$$VERSION" -m "Release v$$VERSION"

test-dist: generate-versions
	uv build
	uvx uv-publish@latest --repo testpypi

release: clean check dist tag git
