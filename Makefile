# ============================================================
# Main Makefile for OWLSM Project
# ============================================================

# ---- Configuration Variables ---------------------------------
# Set DEBUG=1 for debug builds: make DEBUG=1
# Leave unset for release builds: make
VERSION        ?= 1.0.0

# Validate VERSION format (X.Y.Z)
ifneq ($(words $(subst ., ,$(VERSION))),3)
$(error VERSION must be Major.Minor.Patch, got '$(VERSION)')
endif

# ---- Export variables to sub-makefiles -----------------------
export DEBUG
export VERSION

# ---- Directories ---------------------------------------------
SRC_DIR        := src
BUILD_DIR      := build
KERNEL_DIR     := $(SRC_DIR)/Kernel
USERSPACE_DIR  := $(SRC_DIR)/Userspace
TEST_DIR       := $(SRC_DIR)/Tests
UNIT_TEST_DIR  := $(TEST_DIR)/unit_test
AUTOMATION_DIR := $(TEST_DIR)/Automation
AUTOMATION_RESOURCES_DIR := $(AUTOMATION_DIR)/resources

# ---- Binary Paths --------------------------------------------
USER_BIN       := $(USERSPACE_DIR)/owlsm
TEST_BIN       := $(UNIT_TEST_DIR)/unit_tests

# ---- Phony Targets -------------------------------------------
.PHONY: all clean test automation help
.DEFAULT_GOAL := all

# ---- Build Targets -------------------------------------------
all: kernel userspace
	@mkdir -p $(BUILD_DIR)
	@cp -a $(USER_BIN) $(BUILD_DIR)/

kernel:
	@echo "==> Building Kernel (eBPF)..."
	@$(MAKE) -C $(KERNEL_DIR)

userspace: kernel
	@echo "==> Building Userspace..."
	@$(MAKE) -C $(USERSPACE_DIR)

test:
	@echo "==> Building unit tests..."
	@$(MAKE) -C $(UNIT_TEST_DIR)
	@mkdir -p $(BUILD_DIR)
	@cp -a $(TEST_BIN) $(BUILD_DIR)/

automation:
	@echo "==> Building automation resources..."
	@$(MAKE) -C $(AUTOMATION_RESOURCES_DIR)
	@cp -a $(USER_BIN) $(AUTOMATION_DIR)/owlsm
	
clean:
	@echo "==> Cleaning Kernel..."
	@$(MAKE) -C $(KERNEL_DIR) clean
	@echo "==> Cleaning Userspace..."
	@$(MAKE) -C $(USERSPACE_DIR) clean
	@echo "==> Cleaning Tests..."
	@$(MAKE) -C $(UNIT_TEST_DIR) clean
	@$(MAKE) -C $(AUTOMATION_RESOURCES_DIR) clean
	@echo "==> Cleaning build directory..."
	@rm -rf $(BUILD_DIR)

help:
	@echo "OWLSM Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build kernel and userspace (default), copies to build/"
	@echo "  kernel     - Build eBPF kernel code"
	@echo "  userspace  - Build userspace binary"
	@echo "  test       - Build unit tests (copies to build/)"
	@echo "  automation - Build automation resources only"
	@echo "  clean      - Clean all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DEBUG      - Set to 1 for debug build (default: unset = release)"
	@echo "  VERSION    - Version string X.Y.Z (default: $(VERSION))"
	@echo ""
	@echo "Examples:"
	@echo "  make                  # Release build"
	@echo "  make DEBUG=1          # Debug build"
	@echo "  make VERSION=2.0.0    # Custom version"
	@echo "  make test DEBUG=1     # Debug unit tests"
