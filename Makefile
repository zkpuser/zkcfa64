.DEFAULT_GOAL := help

PYTHON ?= python3
BINIUS_TOOLCHAIN ?= 1.97.1
ZEKRA_ARGS ?=
CRC32_ARGS ?=

.PHONY: help check test-provider test-binius test-binius-raw64 test-binius-controls test-binius-research test-plonk test-plonk-experiments test-plonk-research test-zekra test-experiment-data reproduce-zekra crc32

help:
	@printf '%s\n' \
	  'make check          Check layout, maintained links, and script syntax' \
	  'make test-provider  Run maintained provider tests (provider dependencies required)' \
	  'make test-binius    Run default raw24 application tests (Rust $(BINIUS_TOOLCHAIN))' \
	  'make test-binius-raw64    Run the optional raw64 relation tests' \
	  'make test-binius-controls Run membership/stack control tests and compile experiment targets' \
	  'make test-binius-research Run Python experiment-tool tests without proving' \
	  'make test-plonk     Run PLONK core and reissuance tests (stable Rust)' \
	  'make test-plonk-experiments Run PLONK tests and compile the scaling experiment' \
	  'make test-plonk-research Run Python PLONK campaign/scaling tests without proving' \
	  'make test-zekra     Run ZEKRA reproduction-tool tests without Docker' \
	  'make test-experiment-data Run public data export tests without benchmarks' \
	  'make reproduce-zekra Run the isolated upstream CRC32 proof and verification' \
	  'make crc32          Run the full Docker CRC32 reproduction' \
	  '                    Add CRC32_ARGS="--quick" or "--dry-run" as needed'

check:
	$(PYTHON) scripts/check-repository.py

test-provider:
	$(MAKE) -C zkcfa-tracer/provider test

test-binius:
	cd zkcfa-binius64/zkcfa64 && cargo +$(BINIUS_TOOLCHAIN) test --locked --no-default-features --lib --bins

test-binius-raw64:
	cd zkcfa-binius64/zkcfa64 && cargo +$(BINIUS_TOOLCHAIN) test --locked --no-default-features --features raw64 --lib

test-binius-controls:
	cd zkcfa-binius64/zkcfa64 && cargo +$(BINIUS_TOOLCHAIN) test --locked --no-default-features --features construction-control,stack-control --lib --examples

test-binius-research:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s zkcfa-binius64/research/tests -v

test-plonk:
	cd zkcfa-plonk/zkcfa && cargo test --release --locked --no-default-features --lib --bins

test-plonk-experiments:
	cd zkcfa-plonk/zkcfa && cargo test --release --locked --no-default-features --features experiments --lib --examples

test-plonk-research:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s zkcfa-plonk/research/tests -v

crc32:
	bash scripts/run-crc32-pipeline.sh $(CRC32_ARGS)

test-zekra:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s zekra/reproduce/tests -v

test-experiment-data:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s scripts/experiment-data/tests -v

reproduce-zekra:
	$(PYTHON) zekra/reproduce/run_crc32.py $(ZEKRA_ARGS)
