# AGENTS.md - Automation Tests

## Overview

The Automation component contains integration tests for owLSM using the pytest-bdd framework. Tests are written in Gherkin syntax (feature files) with Python step implementations. These tests verify end-to-end functionality by running the actual owLSM binary and validating its behavior.

---

## Project Structure

```
Automation/
├── AGENTS.md                # This file
├── README.md                # Setup and usage documentation
├── conftest.py              # pytest configuration and fixtures
├── pytest.ini               # pytest settings
├── requirements.txt         # Python dependencies
├── features/                # Test implementations
│   ├── all_test.py          # Test scenarios
│   └── *.feature            # Gherkin feature files (if any)
├── common_steps/            # Reusable step definitions
│   └── ...
├── globals/                 # Global state and configuration
│   └── ...
├── state_db/                # State management for tests
│   └── ...
├── Utils/                   # Test utilities and helpers
│   └── ...
├── resources/               # Test resources (compiled binaries, configs)
│   └── ...
└── venv/                    # Python virtual environment (gitignored)
```

---

## Tech Stack

- **Python 3.10+**
- **pytest** - Test runner
- **pytest-bdd** - BDD framework for Gherkin syntax
- **uv** - Package manager

---

## Concepts and Design

### Test Flow
1. Test fixture starts owLSM with specific configuration
2. Test performs system actions (file operations, process execution, etc.)
3. Test validates owLSM events/actions match expected behavior
4. Fixture tears down owLSM

### Key Files
- `conftest.py` - Contains shared fixtures (owLSM process management, etc.)
- `common_steps/` - Reusable Gherkin step implementations
- `globals/` - System-wide test configuration
- `state_db/` - Tracks test state across steps

### Log Files
- `automation.log` - Test framework logs
- `owLSM_output.log` - owLSM stdout (events)
- `owlsm.log` - owLSM internal logger output

---

## How to Add New Tests

1. Create or update feature file in `features/` with Gherkin scenarios:
    - For new product features create new `.feature` file
2. Implement step definitions in `features/` and `common_steps/`
3. Use existing fixtures from `conftest.py` for owLSM lifecycle
4. Add the test scenario to `src/Tests/Automation/features/all_test.py` with a `test_` prefix.
5. Run that single test 


## Important points for new tests
1. Try to use steps that already exists. Only if absolute necessery add new steps.
2. In the steps that we specify the event we are looking for, try to be very specific and specify important expected values. This help us to ensure that we found the correct event and not a similar event.
3. Try to make the tests very reliable and fast.

## Test coverage 
1. When you are thinking about new test scenarios try to coverage as many common situation as possible.
2. tell me what edge cases you think we should tests as well (but don't add edge cases tests until I approve them).


---

## Important Notes

- Tests must run on HOST (not in Docker) - requires kernel access
- Tests require root privileges to run owLSM
- Build with `make automation` before running tests
- See [./README](./README.md) for setup and test execution details.

