Feature: On chmod tests

Scenario: restart_owlsm_twice
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
    And The owLSM process is running
    And I stop the owLSM process
    And The owLSM process is not running
    Then I start the owLSM process
    And The owLSM process is running


Scenario: owlsm_cleans_maps
    Given The owLSM process is running
    And I ensure the directory "/sys/fs/bpf/owLSM" exists
    When I stop the owLSM process
    And I ensure the directory "/sys/fs/bpf/owLSM" does not exist
    Then I start the owLSM process
    And The owLSM process is running