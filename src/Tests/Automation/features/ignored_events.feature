Feature: Ignored events tests

Scenario: related_processes_are_ignored
    Given The owLSM process is running
    When I stop the owLSM process
    And The owLSM process is not running
    And I run the resource "related_process" with arguments "25 /tmp/related_process.log" async and save pid
    Then I start owLSM and ignore the resource pid
    And I dont find the event in output in "25" seconds:
        | process.pid              | <resource_pid>             |
    And I dont find the event in output in "5" seconds:
        | process.ppid             | <resource_pid>             |
    And I dont find the event in output in "5" seconds:
        | data.file.path           | /tmp/related_process.log   |
    And I ensure the file "/tmp/related_process.log" does not exist


Scenario: cached_write_event_reported_only_once
    Given The owLSM process is running
    And I ensure new file "/tmp/cached_write" is created
    When I try to append to the file "/tmp/cached_write" the content "a"
    And I try to append to the file "/tmp/cached_write" the content "b"
    And I try to append to the file "/tmp/cached_write" the content "c"
    And file size of "/tmp/cached_write" is "3" bytes
    Then I find the event in output exactly "1" times in "12" seconds:
        | type            | WRITE               |
        | data.file.path  | /tmp/cached_write   |


Scenario: read_event_disabled_in_config
    Given The owLSM process is running
    And I stop the owLSM process
    And The owLSM process is not running
    And I remove owLSM output log
    And I start the owLSM process with config file "read_event_disabled_in_config.json"
    And The owLSM process is running
    When I ensure new file "/tmp/read_event_disabled" is created
    And I run the command "/usr/bin/cat /tmp/read_event_disabled" sync 
    And I try to append to the file "/tmp/read_event_disabled" the content "b"
    Then I find the event in output in "20" seconds:
        | type           | WRITE                    |
        | data.file.path | /tmp/read_event_disabled |
    And I dont find the event in output in "3" seconds:
        | type | READ  |
    And I stop the owLSM process
    And The owLSM process is not running
    # This step will restart owLSM with default config
    And I start the owLSM process         