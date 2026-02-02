Feature: On exit tests


Scenario: allowed_exit
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    When I fork and child exits with code "7"
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>               |
        | action                   | ALLOW_EVENT                    |
        | type                     | EXIT                           |
        | process.file.path        | <automation_binary_path>       |
        | parent_process.pid       | <automation_pid>               |
        | parent_process.file.path | <automation_binary_path>       |
        | data.exit_code           | 7                              |
        | data.signal              | 0                              |
        
