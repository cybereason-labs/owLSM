Feature: On rename tests

Scenario: allowed_rename
    Given The owLSM process is running
    And I ensure the file "/tmp/test1" exists
    When I run the command "/usr/bin/mv /tmp/test1 /tmp/test2" sync
    And The file "/tmp/test2" should exist "true"
    And I add the path "/tmp/test2" to the file db
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                  |
        | action                            | ALLOW_EVENT                       |
        | type                              | RENAME                            |
        | process.file.path                 | /usr/bin/mv                       |
        | process.cmd                       | /usr/bin/mv /tmp/test1 /tmp/test2 |
        | data.rename.source_file.path      | /tmp/test1                        |
        | data.rename.source_file.type      | REGULAR_FILE                      |
        | data.rename.destination_file.path | /tmp/test2                        |

        

Scenario: blocked_rename
    Given The owLSM process is running
    And I ensure the file "/tmp/test2" exists
    When I run the command "/usr/bin/mv /tmp/test2 /tmp/123.txt.old" sync
    And The file "/tmp/123.txt.old" should exist "false"
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                        |
        | action                            | BLOCK_EVENT                             |
        | type                              | RENAME                                  |
        | process.file.path                 | /usr/bin/mv                             |
        | process.cmd                       | /usr/bin/mv /tmp/test2 /tmp/123.txt.old |
        | data.rename.source_file.path      | /tmp/test2                              |
        | data.rename.source_file.type      | REGULAR_FILE                            |
        | data.rename.destination_file.path | /tmp/123.txt.old                        |
        | matched_rule_id                   | 16                                      |
