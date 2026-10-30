# sqf-lab -- one entry point for tests, native build, benchmarks and packaging.

PY ?= python3
NATIVE ?= 0

.PHONY: help install test test-all lint native bench bench-native clean dist

help:                      ## show this help
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | column -t

install:                   ## editable install with dev extras
	$(PY) -m pip install -e ".[dev]"

test:                      ## fast test suite (pure Python)
	$(PY) -m pytest tests -q

test-all: native           ## full suite including the C++ engines
	SQF_LAB_LIB=$(CURDIR)/cpp/build/libsqf_dual.so $(PY) -m pytest tests -q

lint:                      ## ruff + a compile check of every module
	-$(PY) -m ruff check src tests
	$(PY) -m compileall -q src

native:                    ## build the C++ engines into cpp/build
	$(MAKE) -C cpp NATIVE=$(NATIVE)

bench:                     ## blind benchmark: Python SQF vs Python kangaroo
	$(PY) benchmarks/run_blind_benchmark.py --bits 16 20 24 --trials 3

bench-native: native       ## blind benchmark of the C++ engines
	SQF_LAB_LIB=$(CURDIR)/cpp/build/libsqf_dual.so \
	  $(PY) benchmarks/run_native_benchmark.py --bits 24 28 32 36 40 --trials 3

clean:                     ## remove build artefacts
	rm -rf cpp/build build dist *.egg-info .pytest_cache
	find . -name '__pycache__' -prune -exec rm -rf {} +
