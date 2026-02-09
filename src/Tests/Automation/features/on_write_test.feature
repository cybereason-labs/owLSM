Feature: On write tests

Scenario: allowed_write
    Given The owLSM process is running
    And I ensure new file "/tmp/test1" is created
    And I run the command "chmod 777 /tmp/test1" sync 
    And I try to write to the file "/tmp/test1" the content "aabb"
    And file size of "/tmp/test1" is "4" bytes
    Then I find the event in output in "30" seconds:
        | process.pid           | <automation_pid>         |
        | action                | ALLOW_EVENT              |
        | type                  | WRITE                    |
        | process.file.path     | <automation_binary_path> |
        | data.target.file.path | /tmp/test1               |
        | data.target.file.mode | 511                      |
        | data.target.file.type | REGULAR_FILE             |
        

Scenario: blocked_write
    Given The owLSM process is running
    And I ensure new file "/tmp/blocked_write" is created
    And I run the command "chmod 777 /tmp/blocked_write" sync 
    And I run the command "stat /tmp/blocked_write" sync 
    And I try to write to the file "/tmp/blocked_write" the content "aabb"
    And file size of "/tmp/blocked_write" is "0" bytes
    Then I find the event in output in "30" seconds:
        | process.pid           | <automation_pid>         |
        | action                | BLOCK_EVENT              |
        | type                  | WRITE                    |
        | process.file.path     | <automation_binary_path> |
        | data.target.file.path | /tmp/blocked_write       |
        | matched_rule_id       | 10                       |
