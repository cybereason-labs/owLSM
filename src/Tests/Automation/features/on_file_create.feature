Feature: On file create tests

Scenario: allowed_file_create
    Given The owLSM process is running
    And I ensure new file "/tmp/abc 123 *() aaa T^T^T^Y @@@ **** * * __ _ aaaaaaa.txt4.bjj6" is created
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                                                 |
        | action                    | ALLOW_EVENT                                                      |
        | type                      | FILE_CREATE                                                      |
        | process.file.path         | <automation_binary_path>                                         |
        | data.target.file.path     | /tmp/abc 123 *() aaa T^T^T^Y @@@ **** * * __ _ aaaaaaa.txt4.bjj6 |
        | data.target.file.filename | abc 123 *() aaa T^T^T^Y @@@ **** * * __ _ aaaaaaa.txt4.bjj6      |
        | data.target.file.mode     | 292                                                              |
        | data.target.file.type     | REGULAR_FILE                                                     |
        

Scenario: blocked_file_create
    Given The owLSM process is running
    And I fail to create file "/tmp/g . ! . # . $. ^ . _ aaa 4 5 6 999"
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                         |
        | action                    | BLOCK_EVENT                              |
        | type                      | FILE_CREATE                              |
        | process.file.path         | <automation_binary_path>                 |
        | data.target.file.path     | /tmp/g . ! . # . $. ^ . _ aaa 4 5 6 999  |
        | data.target.file.filename | g . ! . # . $. ^ . _ aaa 4 5 6 999       |
        | data.target.file.mode     | 292                                      |
        | data.target.file.type     | REGULAR_FILE                             |
        | matched_rule_id           | 9                                        |


Scenario: excluded_file_create
    Given The owLSM process is running
    And I ensure new file "/tmp/test_exclude_event" is created
    Then I dont find the event in output in "10" seconds:
        | type                  | FILE_CREATE             |
        | data.target.file.path | /tmp/test_exclude_event |
