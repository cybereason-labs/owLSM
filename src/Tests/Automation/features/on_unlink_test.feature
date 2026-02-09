Feature: On unlink tests

Scenario: allowed_unlink
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    And I run the command "/usr/bin/rm /tmp/test1" sync
    Then I find the event in output in "30" seconds:
        | process.ppid          | <automation_pid>       |
        | action                | ALLOW_EVENT            |
        | type                  | UNLINK                 |
        | process.file.path     | /usr/bin/rm            |
        | process.cmd           | /usr/bin/rm /tmp/test1 |
        | data.target.file.path | /tmp/test1             |


Scenario: blocked_unlink
    Given The owLSM process is running
    And I ensure the file "/tmp/test2" exists
    And I ensure the hard link "/tmp/test2" to "/tmp/test2_hard_link" exists
    And I run the command "/usr/bin/rm /tmp/test2_hard_link" sync
    Then I find the event in output in "30" seconds:
        | process.ppid           | <automation_pid>                 |
        | action                 | BLOCK_EVENT                      |
        | type                   | UNLINK                           |
        | process.file.path      | /usr/bin/rm                      |
        | process.cmd            | /usr/bin/rm /tmp/test2_hard_link |
        | data.target.file.path  | /tmp/test2_hard_link             |
        | data.target.file.nlink | 2                                |
        | matched_rule_id        | 15                               |
