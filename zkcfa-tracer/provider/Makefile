PYTHON ?= python3
export PYTHONDONTWRITEBYTECODE := 1
STATIC_OUT ?= build/static
ARTIFACTS := $(STATIC_OUT)/registry
BINARY := $(STATIC_OUT)/crc32-aarch64
TRACE := $(STATIC_OUT)/trace.log
SHADOW_ARTIFACTS ?= build/shadow

.PHONY: test static shadow container-demo demo clean

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

static:
	$(MAKE) -f Makefile.static OUT=$(STATIC_OUT) all

shadow: static
	PYTHONPATH=. $(PYTHON) -m static.shadow_safe_bundle \
		--input-bundle $(ARTIFACTS) --output $(SHADOW_ARTIFACTS)

container-demo: test static
	$(MAKE) -f Makefile.static OUT=$(STATIC_OUT) qemu-negative
	$(MAKE) -f Makefile.static OUT=$(STATIC_OUT) reproducible

demo:
	docker compose run --build --rm provider

clean:
	rm -rf build/static build/static-repro build/shadow
