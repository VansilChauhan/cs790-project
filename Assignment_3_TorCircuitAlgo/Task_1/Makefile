# Makefile

VENV_DIR=venv
PYTHON=$(VENV_DIR)/bin/python
PIP=$(VENV_DIR)/bin/pip
REQUIREMENTS=requirements.txt
SCRIPT=task_1.py

.PHONY: all setup run clean

all: setup run

# Step 1: Setup virtual environment and install dependencies
setup:
	@test -d $(VENV_DIR) || python3 -m venv $(VENV_DIR)
	$(PIP) install --upgrade pip
	$(PIP) install -r $(REQUIREMENTS)

# Step 2: Run the script
run:
	$(PYTHON) $(SCRIPT)

# Cleanup (optional)
clean:
	rm -rf $(VENV_DIR)
