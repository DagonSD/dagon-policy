# dagon-policy Makefile
# Usage: make <target>  |  make help

KYVERNO_VERSION  := v1.12.5
CONFTEST_VERSION := 0.50.0
OPA_VERSION      := v0.68.0

# Detect OS for install-tools target
UNAME := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(findstring MINGW,$(UNAME)),MINGW)
  OS_TYPE := Windows
else ifeq ($(findstring MSYS,$(UNAME)),MSYS)
  OS_TYPE := Windows
else ifeq ($(UNAME),Windows)
  OS_TYPE := Windows
else ifeq ($(UNAME),Darwin)
  OS_TYPE := Darwin
else
  OS_TYPE := Linux
endif

.PHONY: help test test-kyverno test-kyverno-baseline test-kyverno-regulated \
        test-kyverno-tenant test-rego test-rego-azure test-rego-common \
        lint conftest-azure conftest-aws install-tools check-tools

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ── Tests ─────────────────────────────────────────────────────────────────────

test: test-kyverno test-rego ## Run all tests (Kyverno + Rego)

test-kyverno: ## Run all Kyverno CLI unit tests
	kyverno test kyverno/baseline/ --detailed-results
	kyverno test kyverno/regulated/ --detailed-results
	kyverno test kyverno/tenant-isolation/ --detailed-results

test-kyverno-baseline: ## Run baseline policy tests only
	kyverno test kyverno/baseline/ --detailed-results

test-kyverno-regulated: ## Run regulated policy tests only
	kyverno test kyverno/regulated/ --detailed-results

test-kyverno-tenant: ## Run tenant-isolation policy tests only
	kyverno test kyverno/tenant-isolation/ --detailed-results

test-rego: test-rego-azure test-rego-common ## Run all OPA/Rego unit tests

test-rego-azure: ## Run Azure IaC rule unit tests
	opa test iac/azure/ --verbose

test-rego-common: ## Run common IaC rule unit tests
	opa test iac/common/ --verbose

# ── Linting ───────────────────────────────────────────────────────────────────

lint: ## Lint all YAML files
	yamllint -c .yamllint.yaml kyverno/

# ── Conftest (against a real plan) ────────────────────────────────────────────

conftest-azure: ## Validate an Azure plan: make conftest-azure PLAN=path/to/plan.json
	@test -n "$(PLAN)" || (echo "Usage: make conftest-azure PLAN=path/to/plan.json" && exit 1)
	conftest test $(PLAN) --policy iac/azure/ --policy iac/common/

conftest-aws: ## Validate an AWS plan: make conftest-aws PLAN=path/to/plan.json
	@test -n "$(PLAN)" || (echo "Usage: make conftest-aws PLAN=path/to/plan.json" && exit 1)
	conftest test $(PLAN) --policy iac/aws/ --policy iac/common/

# ── Tool Installation ─────────────────────────────────────────────────────────

install-tools: ## Install Kyverno CLI, OPA, and Conftest locally
ifeq ($(OS_TYPE),Windows)
	@echo "Detected Windows. Installing via winget + direct download..."
	@echo "Installing Kyverno CLI (latest via winget)..."
	@winget install kyverno.kyverno --accept-source-agreements --accept-package-agreements || true
	@echo "Installing OPA (latest via winget)..."
	@winget install open-policy-agent.opa --accept-source-agreements --accept-package-agreements || true
	@echo "Installing Conftest $(CONFTEST_VERSION) to ~/.local/bin ..."
	@mkdir -p "$(USERPROFILE)/.local/bin"
	@curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v$(CONFTEST_VERSION)/conftest_$(CONFTEST_VERSION)_Windows_x86_64.zip" \
	  -o "$(TEMP)/conftest.zip"
	@unzip -o "$(TEMP)/conftest.zip" conftest.exe -d "$(USERPROFILE)/.local/bin/"
	@echo "All tools installed. Add %USERPROFILE%\.local\bin to your PATH if conftest is not found."
else ifeq ($(OS_TYPE),Darwin)
	@echo "Detected macOS. Installing via Homebrew..."
	@brew install kyverno opa conftest
else
	@echo "Detected Linux. Downloading binaries to /usr/local/bin..."
	@curl -sSL "https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno_linux_amd64.tar.gz" \
	  | tar -xz -C /usr/local/bin kyverno
	@curl -sSL "https://github.com/open-policy-agent/opa/releases/download/$(OPA_VERSION)/opa_linux_amd64_static" \
	  -o /usr/local/bin/opa && chmod +x /usr/local/bin/opa
	@curl -sSL "https://github.com/open-policy-agent/conftest/releases/download/v$(CONFTEST_VERSION)/conftest_$(CONFTEST_VERSION)_Linux_x86_64.tar.gz" \
	  | tar -xz -C /usr/local/bin conftest
	@echo "All tools installed."
endif

check-tools: ## Verify required tools are installed and report versions
	@command -v kyverno  >/dev/null 2>&1 || (echo "ERROR: kyverno not found. Run: make install-tools" && exit 1)
	@command -v opa      >/dev/null 2>&1 || (echo "ERROR: opa not found. Run: make install-tools" && exit 1)
	@command -v conftest >/dev/null 2>&1 || (echo "ERROR: conftest not found. Run: make install-tools" && exit 1)
	@echo "All required tools are present."
	@kyverno version
	@opa version
	@conftest --version
