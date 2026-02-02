Feature: On chown tests

Scenario: allowed_chown
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    When I run the command "/usr/bin/chown 1000:1000 /tmp/test1" sync
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>                     |
        | action                   | ALLOW_EVENT                          |
        | type                     | CHOWN                                |
        | process.file.path        | /usr/bin/chown                       |
        | process.cmd              | /usr/bin/chown 1000:1000 /tmp/test1  |
        | data.file.path           | /tmp/test1                           |


Scenario: blocked_chown
    Given The owLSM process is running
    And I ensure the file "/tmp/test2" exists
    When I run the command "/usr/bin/chown 1000:1000 /tmp/test2" sync
    And I run the command "/usr/bin/chown 7:7 /tmp/test2" sync
    Then I find the event in output in "30" seconds:
        | process.ppid             | <automation_pid>               |
        | action                   | BLOCK_EVENT                    |
        | type                     | CHOWN                          |
        | process.file.path        | /usr/bin/chown                 |
        | process.file.filename    | chown                          |
        | process.cmd              | /usr/bin/chown 7:7 /tmp/test2  |
        | parent_process.file.path | <automation_binary_path>       |
        | parent_process.pid       | <automation_pid>               |
        | data.file.path           | /tmp/test2                     |
        | data.file.filename       | test2                          |
        | data.file.owner.uid      | 1000                           |
        | data.file.owner.gid      | 1000                           |
        | matched_rule_id          | 7                              |
