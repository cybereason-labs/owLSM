Feature: stdio types tests

Scenario: allowed_stdio_redirection
Given The owLSM process is running
And I ensure the file "/tmp/test1" exists
And I ensure the socket "/tmp/test2.sock" exists
When I run the resource "stdio_redirection" with arguments "/usr/bin/ls /tmp/test1 /tmp/test2.sock" sync
Then I find the event in output in "30" seconds:
    | action                                                              | ALLOW_EVENT               |
    | type                                                                | EXEC                      |
    | process.file.filename                                               | stdio_redirection         |
    | parent_process.ppid                                                 | <automation_pid>          |
    | parent_process.file.filename                                        | stdio_redirection         |
    | parent_process.file.type                                            | REGULAR_FILE              |
    | data.new_process.file.path                                          | /usr/bin/ls               |
    | data.new_process.file.filename                                      | ls                        |
    | data.new_process.cmd                                                | /usr/bin/ls               |
    | data.new_process.stdio_file_descriptors_at_process_creation.stdin   | FIFO                      |
    | data.new_process.stdio_file_descriptors_at_process_creation.stdout  | REGULAR_FILE              |
    | data.new_process.stdio_file_descriptors_at_process_creation.stderr  | SOCKET                    |