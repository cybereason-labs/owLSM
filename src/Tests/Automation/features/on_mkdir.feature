Feature: On mkdir tests

Scenario: allowed_mkdir
    Given The owLSM process is running
    And I ensure new directory "/tmp/abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_mkdir" is created with mode "750"
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                                    |
        | action                    | ALLOW_EVENT                                         |
        | type                      | MKDIR                                               |
        | process.file.path         | <automation_binary_path>                            |
        | data.target.file.path     | /tmp/abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_mkdir     |
        | data.target.file.filename | abc 123 aaa T^T^T^Y @@@ aaaaaaa_test_mkdir          |
        | data.target.file.type     | DIRECTORY                                           |
        | data.target.file.mode     | 488                                                 |
        

Scenario: blocked_mkdir
    Given The owLSM process is running
    And I fail to create directory "/tmp/g . ! . # . $. ^ . _ aaa 4 5 6 999_mkdir"
    Then I find the event in output in "10" seconds:
        | process.pid               | <automation_pid>                                  |
        | action                    | BLOCK_EVENT                                       |
        | type                      | MKDIR                                             |
        | process.file.path         | <automation_binary_path>                          |
        | data.target.file.path     | /tmp/g . ! . # . $. ^ . _ aaa 4 5 6 999_mkdir     |
        | data.target.file.filename | g . ! . # . $. ^ . _ aaa 4 5 6 999_mkdir           |
        | data.target.file.type     | DIRECTORY                                         |
        | matched_rule_id           | 28                                                |


Scenario: excluded_mkdir
    Given The owLSM process is running
    And I ensure new directory "/tmp/test_exclude_mkdir_event" is created
    Then I dont find the event in output in "10" seconds:
        | type                  | MKDIR                              |
        | data.target.file.path | /tmp/test_exclude_mkdir_event      |


Scenario: mkdir_and_rmdir_directory_tree
    Given The owLSM process is running
    And I ensure the directory "/tmp/level1" does not exist
    And I run the command "/usr/bin/mkdir -p /tmp/level1/level2/level3" sync
    And I add the path "/tmp/level1" to the file db
    And I run the command "/usr/bin/rm -fRd /tmp/level1" sync
    Then I find the event in output in "30" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | MKDIR                         |
        | process.file.path     | /usr/bin/mkdir                |
        | data.target.file.path | /tmp/level1                   |
    Then I find the event in output in "10" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | MKDIR                         |
        | process.file.path     | /usr/bin/mkdir                |
        | data.target.file.path | /tmp/level1/level2            |
    Then I find the event in output in "10" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | MKDIR                         |
        | process.file.path     | /usr/bin/mkdir                |
        | data.target.file.path | /tmp/level1/level2/level3     |
    Then I find the event in output in "10" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | RMDIR                         |
        | process.file.path     | /usr/bin/rm                   |
        | data.target.file.path | /tmp/level1/level2/level3     |
    Then I find the event in output in "10" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | RMDIR                         |
        | process.file.path     | /usr/bin/rm                   |
        | data.target.file.path | /tmp/level1/level2            |
    Then I find the event in output in "10" seconds:
        | process.ppid          | <automation_pid>              |
        | action                | ALLOW_EVENT                   |
        | type                  | RMDIR                         |
        | process.file.path     | /usr/bin/rm                   |
        | data.target.file.path | /tmp/level1                   |
