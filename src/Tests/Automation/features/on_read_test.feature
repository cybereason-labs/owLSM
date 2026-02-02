Feature: On read tests

Scenario: allowed_read
    Given The owLSM process is running
    And I ensure new file "/tmp/test1" is created
    When I run the command "/usr/bin/chmod 777 /tmp/test1" sync
    And I run the command "/usr/bin/cat /tmp/test1" sync 
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>               |
        | action                   | ALLOW_EVENT                    |
        | type                     | READ                           |
        | process.file.path        | /usr/bin/cat                   |
        | process.cmd              | /usr/bin/cat /tmp/test1        |
        | data.file.path           | /tmp/test1                     |
        | data.file.mode           | 511                            |
        | data.file.type           | REGULAR_FILE                   |
        

Scenario: blocked_read
    Given The owLSM process is running
    And I ensure new file "/tmp/blocked_read" is created
    And I run the command "chmod 777 /tmp/blocked_read" sync 
    When I run the command "/usr/bin/wc /tmp/blocked_read" sync 
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>               |
        | action                   | BLOCK_EVENT                    |
        | type                     | READ                           |
        | process.file.path        | /usr/bin/wc                    |
        | process.cmd              | /usr/bin/wc /tmp/blocked_read  |
        | data.file.path           | /tmp/blocked_read              |
        | matched_rule_id          | 11                             |
