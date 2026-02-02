Feature: On fork tests


Scenario: allowed_fork
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    When I fork and child exits with code "7"
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>               |
        | parent_process.pid       | <automation_pid>               |
        | parent_process.file.type | REGULAR_FILE                   |
        | action                   | ALLOW_EVENT                    |
        | type                     | FORK                           |
        | process.file.path        | <automation_binary_path>       |
        
