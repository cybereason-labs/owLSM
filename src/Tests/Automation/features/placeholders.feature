Feature: Placeholder expansion tests

Scenario: placeholder_expand_all_three_fields_match_blocks_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/placeholder_blocked_file" exists
    When I run the command "/usr/bin/chmod 777 /tmp/placeholder_blocked_file" sync
    Then I find the event in output in "30" seconds:
        | process.ppid                      | <automation_pid>                                        |
        | action                            | BLOCK_EVENT                                             |
        | type                              | CHMOD                                                   |
        | process.file.path                 | /usr/bin/chmod                                          |
        | process.file.filename             | chmod                                                   |
        | data.target.file.path             | /tmp/placeholder_blocked_file                           |
        | matched_rule_id                   | 50                                                      |
        | matched_rule_metadata.description | Block file ops matching all three placeholder conditions |


Scenario: placeholder_expand_two_of_three_fields_match_allows_chmod
    Given The owLSM process is running
    And I ensure the file "/tmp/ph_nomatch_test" exists
    When I run the command "/usr/bin/chmod 777 /tmp/ph_nomatch_test" sync
    Then I find the event in output in "30" seconds:
        | process.ppid          | <automation_pid>      |
        | type                  | CHMOD                 |
        | process.file.path     | /usr/bin/chmod        |
        | process.file.filename | chmod                 |
        | data.target.file.path | /tmp/ph_nomatch_test  |
        | action                | ALLOW_EVENT           |
    And I dont find the event in output in "5" seconds:
        | type            | CHMOD       |
        | matched_rule_id | 50          |
