DOCKER_TAG = dev

GULP := node_modules/.bin/gulp

# Unless the user has specified otherwise in their environment, it's probably a
# good idea to refuse to install unless we're in an activated virtualenv.
ifndef PIP_REQUIRE_VIRTUALENV
PIP_REQUIRE_VIRTUALENV = 1
endif
export PIP_REQUIRE_VIRTUALENV

.PHONY: default
default: test

build/manifest.json: node_modules/.uptodate
	$(GULP) build

## Clean up runtime artifacts (needed after a version update)
.PHONY: clean
clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete
	rm -f node_modules/.uptodate .pydeps
	rm -rf build

## Run the development H server locally
.PHONY: dev
dev: build/manifest.json .pydeps
	@bin/hypothesis --dev init
	@bin/hypothesis devserver

## Build hypothesis/hypothesis docker image
.PHONY: docker
docker:
	git archive HEAD | docker build -t hypothesis/hypothesis:$(DOCKER_TAG) -

## Run test suite
.PHONY: test
test: node_modules/.uptodate
	@pip install -q tox
	tox
	$(GULP) test

.PHONY: test-py3
test-py3: node_modules/.uptodate
	@pip install -q tox
	@mkdir -p .tox
	@ # Ensure stdout is blocking. Travis appears to turn on O_NONBLOCK on stdout by default which
	@ # can cause `tee` to fail if it receives `EAGAIN`. Requires Python >= 3.5.
	@ # See https://github.com/travis-ci/travis-ci/issues/4704
	@ python3 -c 'import os, sys; os.set_blocking(sys.stdout.fileno(), True);'
	# 1. Run tox, configured to print just one line per error in the form `{path}:{line no}:{line}`.
	# 2. Extract unique error locations and write to file.
	tox -e py36 -- --tb=line --no-print-logs tests/h/ | tee .tox/py36-log
	cat .tox/py36-log | egrep -o '/h/[^:]+:[0-9]+:' | sort | uniq > tests/py3-actual-failures.txt
	# 3. Compare actual and expected failures, this command will fail if they differ.
	diff -u tests/py3-expected-failures.txt tests/py3-actual-failures.txt

.PHONY: lint
lint: .pydeps
	flake8 h
	flake8 tests

################################################################################

# Fake targets to aid with deps installation
.pydeps: requirements.txt
	@echo installing python dependencies
	@pip install --use-wheel -r requirements-dev.in tox
	@touch $@

node_modules/.uptodate: package.json
	@echo installing javascript dependencies
	@node_modules/.bin/check-dependencies 2>/dev/null || npm install
	@touch $@

# Self documenting Makefile
.PHONY: help
help:
	@echo "The following targets are available:"
	@echo " clean      Clean up runtime artifacts (needed after a version update)"
	@echo " dev        Run the development H server locally"
	@echo " docker     Build hypothesis/hypothesis docker image"
	@echo " test       Run the test suite (default)"
