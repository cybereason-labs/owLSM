Feature: Rules with keywords tests

Scenario: keyword_with_all_modifier
    Given The owLSM process is running
    And I ensure the file "/tmp/test_keywords_all_modifier" exists
    When I run the command "/usr/bin/chmod 777 /tmp/test_keywords_all_modifier" sync
    Then I find the event in output in "20" seconds:
        | action                   | BLOCK_EVENT                        |
        | type                     | CHMOD                              |
        | process.file.path        | /usr/bin/chmod                     |
        | data.file.path           | /tmp/test_keywords_all_modifier    |
        | matched_rule_id          | 24                                 |


Scenario: multi_keyword_rule
    Given The owLSM process is running
    And I ensure the file "/tmp/test_keywords_modifier" exists
    When I run the command "/usr/bin/chmod 755 /tmp/test_keywords_modifier" sync
    Then I find the event in output in "20" seconds:
        | action                   | BLOCK_EVENT                        |
        | type                     | CHMOD                              |
        | process.file.path        | /usr/bin/chmod                     |
        | data.file.path           | /tmp/test_keywords_modifier        |
        | matched_rule_id          | 25                                 |


Scenario: multi_event_keyword_rule
    Given The owLSM process is running
    And I ensure the file "/tmp/multi_event_keyword_chmod" exists
    And I ensure the file "/tmp/multi_event_keyword_rename_src" exists
    When I chmod the file "/tmp/multi_event_keyword_chmod" to "777"
    And I rename the file "/tmp/multi_event_keyword_rename_src" to "/tmp/multi_event_keyword_rename_dst"
    And I run the command "/usr/bin/echo multi_event_keyword_exec_cmd please pass" sync
    And I ensure the file "/tmp/multi_event_keyword_rename_dst" does not exist
    Then I find the event in output in "20" seconds:
        | action                      | ALLOW_EVENT                                            |
        | type                        | CHMOD                                                  |
        | data.file.path              | /tmp/multi_event_keyword_chmod                         |
        | data.requested_mode         | 511                                                    |
        | matched_rule_id             | 26                                                     |
    And I find the event in output in "10" seconds:
        | action                      | ALLOW_EVENT                                            |
        | type                        | RENAME                                                 |
        | data.source_file.path       | /tmp/multi_event_keyword_rename_src                    |
        | data.destination_file.path  | /tmp/multi_event_keyword_rename_dst                    |
        | matched_rule_id             | 26                                                     |
    And I find the event in output in "10" seconds:
        | action                      | ALLOW_EVENT                                            |
        | type                        | EXEC                                                   |
        | data.new_process.file.path  | /usr/bin/echo                                          |
        | data.new_process.cmd        | /usr/bin/echo multi_event_keyword_exec_cmd please pass |
        | matched_rule_id             | 26                                                     |
    And I find the event in output in "10" seconds:
        | action                      | ALLOW_EVENT                                            |
        | type                        | UNLINK                                                 |
        | data.file.path              | /tmp/multi_event_keyword_rename_dst                    |
        | matched_rule_id             | 0                                                      |
    And I dont find the event in output in "10" seconds:
        | action                      | ALLOW_EVENT                                            |
        | type                        | UNLINK                                                 |
        | matched_rule_id             | 26                                                     |
        | matched_rule_metadata.description    | Multi-event keywords - tests keyword expansion across different event types |