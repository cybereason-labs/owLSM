Feature: logger tests

Scenario: owLSM_log_contains_starting_message
    Given The owLSM process is running
    Then I ensure owLSM log contains "Starting OWLSM. Version:"