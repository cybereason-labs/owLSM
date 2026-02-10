Feature: On rmdir tests

Scenario: allowed_rmdir
    Given The owLSM process is running
    And I ensure the directory "/tmp/abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_rmdir" exists
    And I ensure the directory "/tmp/abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_rmdir" does not exist
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                                    |
        | action                    | ALLOW_EVENT                                         |
        | type                      | RMDIR                                               |
        | process.file.path         | <automation_binary_path>                            |
        | data.target.file.path     | /tmp/abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_rmdir     |
        | data.target.file.filename | abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_rmdir           |
        | data.target.file.type     | DIRECTORY                                           |
        

Scenario: blocked_rmdir
    Given The owLSM process is running
    And I ensure the directory "/tmp/aaa_blocked_rmdir_test_bbb" exists
    And I fail to remove directory "/tmp/aaa_blocked_rmdir_test_bbb"
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                       |
        | action                    | BLOCK_EVENT                            |
        | type                      | RMDIR                                  |
        | process.file.path         | <automation_binary_path>               |
        | data.target.file.path     | /tmp/aaa_blocked_rmdir_test_bbb        |
        | data.target.file.filename | aaa_blocked_rmdir_test_bbb             |
        | data.target.file.type     | DIRECTORY                              |
        | matched_rule_id           | 30                                     |


Scenario: excluded_rmdir
    Given The owLSM process is running
    And I ensure the directory "/tmp/test_exclude_rmdir_event" exists
    And I ensure the directory "/tmp/test_exclude_rmdir_event" does not exist
    Then I dont find the event in output in "10" seconds:
        | type                  | RMDIR                              |
        | data.target.file.path | /tmp/test_exclude_rmdir_event      |
