CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c17
LDFLAGS = -lpcap

SRC = src/*.c
TARGET = ipk-L2L3-scan

PACK = xcernoj00

VENV_DIR ?= .venv
PYTHON ?= python3
VENV_PY := $(VENV_DIR)/bin/python
PIP := $(VENV_DIR)/bin/pip
PYTEST := $(VENV_DIR)/bin/pytest

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

# Create a local virtualenv and install python test deps into it
venv:
	@echo "Preparing Python venv in $(VENV_DIR)"
	@test -x "$(VENV_PY)" || $(PYTHON) -m venv "$(VENV_DIR)"
	@$(PIP) -q install --upgrade pip
	@$(PIP) -q install pytest

test-warning:
	@if [ ! -x "$(VENV_PY)" ]; then \
		echo "WARNING: This will create a Python virtual environment and install pytest."; \
		printf "Continue? [y/N] "; \
		read ans; \
		case $$ans in \
			y|Y) ;; \
			*) echo "Aborted."; exit 1 ;; \
		esac; \
	fi

# Optional: enforce running tests as root (since you want to test scanning)
test-root-check:
	@id -u | grep -q '^0$$' || (echo "ERROR: run tests as root: sudo make test" && exit 1)

test: test-warning test-root-check all venv 
	@echo "Running tests"
	$(VENV_PY) -m pytest -v tests/test_all.py

pack: clean $(PACK).zip

$(PACK).zip: 
	zip -r $@ src/*.h src/*.c Makefile tests/test_all.py LICENSE README.md CHANGELOG.md Images/*

NixDevShellName:
	@echo c

clean:
	rm -f $(TARGET) $(PACK).zip

clean-venv:
	rm -rf $(VENV_DIR)

.PHONY: all venv test test-root-check clean clean-venv pack NixDevShellName test-warning
