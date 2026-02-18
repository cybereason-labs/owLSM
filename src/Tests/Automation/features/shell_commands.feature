Feature: Shell commands tests

Scenario Outline: multiple_unchained_shell_commands_same_shell_instance
    Given The owLSM process is running
    And I ensure the file "/tmp/shell_command_non_existing_file_1" does not exist
    When I run shell commands with shell "<shell_path>" and save shell pid:
        | echo 123 > /tmp/shell_command_non_existing_file_1 |
        | . /tmp/shell_command_non_existing_file_1     |
    And I add the path "/tmp/shell_command_non_existing_file_1" to the file db
    Then I find the event in output in "30" seconds:
        | type                     | FILE_CREATE                                       |
        | process.pid              | <shell_pid>                                       |
        | process.ppid             | <automation_pid>                                  |
        | process.file.filename    | <shell_file>                                      |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_1 |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_1            |
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                             |
        | process.pid              | <shell_pid>                                       |
        | process.ppid             | <automation_pid>                                  |
        | process.file.filename    | <shell_file>                                      |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_1 |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_1            |
    And I find the event in output in "10" seconds:
        | type                     | READ                                          |
        | process.pid              | <shell_pid>                                   |
        | process.ppid             | <automation_pid>                              |
        | process.file.filename    | <shell_file>                                  |
        | process.shell_command    | . /tmp/shell_command_non_existing_file_1 |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_1        |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: chained_shell_command_find_all_events
    Given The owLSM process is running
    And I ensure the file "/tmp/shell_command_non_existing_file_1" exists
    And I ensure the file "/tmp/shell_command_non_existing_file_2" does not exist
    And I ensure the file "/tmp/shell_command_non_existing_file_2.1" does not exist
    When I run shell command "echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1" with shell "<shell_path>" and save shell pid
    And I add the path "/tmp/shell_command_non_existing_file_2" to the file db
    And I add the path "/tmp/shell_command_non_existing_file_2.1" to the file db
    Then I find the event in output in "30" seconds:
        | type                     | FILE_CREATE                                                                                                                                              |
        | process.pid              | <shell_pid>                                                                                                                                              |
        | process.ppid             | <automation_pid>                                                                                                                                         |
        | process.file.filename    | <shell_file>                                                                                                                                             |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1  |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_2                                                                                                                   |
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                                                                                                                                    |
        | process.pid              | <shell_pid>                                                                                                                                              |
        | process.ppid             | <automation_pid>                                                                                                                                         |
        | process.file.filename    | <shell_file>                                                                                                                                             |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1  |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_2                                                                                                                   |
    And I find the event in output in "10" seconds:
        | type                     | READ                                                                                                                                                     |
        | process.pid              | <shell_pid>                                                                                                                                              |
        | process.ppid             | <automation_pid>                                                                                                                                         |
        | process.file.filename    | <shell_file>                                                                                                                                             |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1  |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_1                                                                                                                   |
    And I find the event in output in "10" seconds:
        | type                     | FILE_CREATE                                                                                                                                              |
        | process.pid              | <shell_pid>                                                                                                                                              |
        | process.ppid             | <automation_pid>                                                                                                                                         |
        | process.file.filename    | <shell_file>                                                                                                                                             |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1  |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_2.1                                                                                                                 |
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                                                                                                                                    |
        | process.pid              | <shell_pid>                                                                                                                                              |
        | process.ppid             | <automation_pid>                                                                                                                                         |
        | process.file.filename    | <shell_file>                                                                                                                                             |
        | process.shell_command    | echo 123 > /tmp/shell_command_non_existing_file_2; . /tmp/shell_command_non_existing_file_1 && echo abc > /tmp/shell_command_non_existing_file_2.1  |
        | data.target.file.path    | /tmp/shell_command_non_existing_file_2.1                                                                                                                 |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: mixed_shell_builtin_and_external_commands
    Given The owLSM process is running
    And I ensure the file "/tmp/both" exists
    When I run shell command "chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both" with shell "<shell_path>" and save shell pid
    # chmod EXEC: parent_process is original shell, process is forked shell, data.target.process is chmod
    Then I find the event in output in "30" seconds:
        | type                              | EXEC                                                                       |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.ppid               | <automation_pid>                                                           |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
        | data.target.process.file.filename | chmod                                                                      |
        | data.target.process.cmd           | chmod 777 /tmp/both                                                        |
        | data.target.process.shell_command |                                                                            |
    # chmod CHMOD event: process is chmod, parent is original shell
    And I find the event in output in "10" seconds:
        | type                              | CHMOD                                                                      |
        | process.ppid                      | <shell_pid>                                                                |
        | process.file.filename             | chmod                                                                      |
        | process.cmd                       | chmod 777 /tmp/both                                                        |
        | process.shell_command             |                                                                            |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
        | data.target.file.path             | /tmp/both                                                                  |
    # chmod EXIT event
    And I find the event in output in "10" seconds:
        | type                              | EXIT                                                                       |
        | process.ppid                      | <shell_pid>                                                                |
        | process.file.filename             | chmod                                                                      |
        | process.cmd                       | chmod 777 /tmp/both                                                        |
        | process.shell_command             |                                                                            |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
    # echo: shell builtin - shell does the write, process (shell) has shell_command
    And I find the event in output in "10" seconds:
        | type                              | WRITE                                                                      |
        | process.pid                       | <shell_pid>                                                                |
        | process.ppid                      | <automation_pid>                                                           |
        | process.file.filename             | <shell_file>                                                               |
        | process.shell_command             | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
        | data.target.file.path             | /tmp/both                                                                  |
    # rm EXEC: parent_process is original shell, data.target.process is rm
    And I find the event in output in "10" seconds:
        | type                              | EXEC                                                                       |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
        | data.target.process.file.filename | rm                                                                         |
        | data.target.process.cmd           | rm -f /tmp/both                                                            |
        | data.target.process.shell_command |                                                                            |
    # rm UNLINK event: process is rm, parent is original shell
    And I find the event in output in "10" seconds:
        | type                              | UNLINK                                                                     |
        | process.ppid                      | <shell_pid>                                                                |
        | process.file.filename             | rm                                                                         |
        | process.cmd                       | rm -f /tmp/both                                                            |
        | process.shell_command             |                                                                            |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
        | data.target.file.path             | /tmp/both                                                                  |
    # rm EXIT event
    And I find the event in output in "10" seconds:
        | type                              | EXIT                                                                       |
        | process.ppid                      | <shell_pid>                                                                |
        | process.file.filename             | rm                                                                         |
        | process.cmd                       | rm -f /tmp/both                                                            |
        | process.shell_command             |                                                                            |
        | parent_process.pid                | <shell_pid>                                                                |
        | parent_process.shell_command      | chmod 777 /tmp/both && echo 'abc 123 !@#' > /tmp/both; rm -f /tmp/both     |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: shell_exits_before_child_process
    Given The owLSM process is running
    When I run shell command "sleep 3 & sleep 1; disown; exit" with shell "<shell_path>" and timeout "5" and save shell pid
    # FORK: shell forks to run sleep 3 in background. Parent (shell) has shell_command.
    Then I find the event in output in "30" seconds:
        | type                              | FORK                       |
        | parent_process.pid                | <shell_pid>                |
        | parent_process.ppid               | <automation_pid>           |
        | parent_process.file.filename      | <shell_file>               |
        | parent_process.shell_command      | sleep 3 & sleep 1; disown; exit    |
    # EXEC: forked shell execs to sleep. Parent is shell (still running sleep 1) with shell_command.
    And I find the event in output in "10" seconds:
        | type                              | EXEC                       |
        | parent_process.pid                | <shell_pid>                |
        | parent_process.ppid               | <automation_pid>           |
        | parent_process.shell_command      | sleep 3 & sleep 1; disown; exit    |
        | data.target.process.file.filename | sleep                      |
        | data.target.process.cmd           | sleep 3                    |
        | data.target.process.shell_command |                            |
    # EXIT (shell): shell exits after sleep 1 completes, still has shell_command
    And I find the event in output in "10" seconds:
        | type                              | EXIT                       |
        | process.pid                       | <shell_pid>                |
        | process.ppid                      | <automation_pid>           |
        | process.file.filename             | <shell_file>               |
        | process.shell_command             | sleep 3 & sleep 1; disown; exit    |
    # EXIT (sleep): sleep 3 exits 2 seconds after shell. Parent is still shell (shell_pid) but parent no longer has shell_command.
    And I find the event in output in "10" seconds:
        | type                              | EXIT                       |
        | process.ppid                      | <shell_pid>                |
        | process.file.filename             | sleep                      |
        | process.cmd                       | sleep 3                    |
        | process.shell_command             |                            |
        | parent_process.pid                | <shell_pid>                |
        | parent_process.shell_command      |                            |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: shell_exec_to_another_process
    Given The owLSM process is running
    And I ensure the file "/tmp/shell_exec" does not exist
    When I run shell command "echo 123 > /tmp/shell_exec; exec cat /tmp/shell_exec" with shell "<shell_path>" and save shell pid
    And I add the path "/tmp/shell_exec" to the file db
    # echo: shell builtin - shell creates and writes to file with shell_command
    Then I find the event in output in "30" seconds:
        | type                              | FILE_CREATE                                          |
        | process.pid                       | <shell_pid>                                          |
        | process.ppid                      | <automation_pid>                                     |
        | process.file.filename             | <shell_file>                                         |
        | process.shell_command             | echo 123 > /tmp/shell_exec; exec cat /tmp/shell_exec |
        | data.target.file.path             | /tmp/shell_exec                                      |
    And I find the event in output in "10" seconds:
        | type                              | WRITE                                                |
        | process.pid                       | <shell_pid>                                          |
        | process.ppid                      | <automation_pid>                                     |
        | process.file.filename             | <shell_file>                                         |
        | process.shell_command             | echo 123 > /tmp/shell_exec; exec cat /tmp/shell_exec |
        | data.target.file.path             | /tmp/shell_exec                                      |
    # exec: shell execs to cat. Old process (shell) has shell_command, new process (cat) does not.
    And I find the event in output in "10" seconds:
        | type                              | EXEC                                                 |
        | process.pid                       | <shell_pid>                                          |
        | process.ppid                      | <automation_pid>                                     |
        | process.file.filename             | <shell_file>                                         |
        | process.shell_command             | echo 123 > /tmp/shell_exec; exec cat /tmp/shell_exec |
        | data.target.process.file.filename | cat                                                  |
        | data.target.process.cmd           | cat /tmp/shell_exec                                  |
        | data.target.process.shell_command |                                                      |
    # read: cat reads from file. Neither process nor parent has shell_command.
    And I find the event in output in "10" seconds:
        | type                              | READ                                                 |
        | process.pid                       | <shell_pid>                                          |
        | process.ppid                      | <automation_pid>                                     |
        | process.file.filename             | cat                                                  |
        | process.cmd                       | cat /tmp/shell_exec                                  |
        | process.shell_command             |                                                      |
        | parent_process.shell_command      |                                                      |
        | data.target.file.path             | /tmp/shell_exec                                      |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: shell_starts_before_owlsm
    Given I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/first_readline_missed" does not exist
    And I ensure the file "/tmp/second_readline_seen" does not exist
    When I spawn a persistent shell "<shell_path>" and save it
    And I start the owLSM process
    And The owLSM process is running
    And I add the path "/tmp/first_readline_missed" to the file db
    And I add the path "/tmp/second_readline_seen" to the file db
    And I send command "echo 123 > /tmp/first_readline_missed" to the persistent shell
    And I send command "echo 456 > /tmp/second_readline_seen" to the persistent shell
    # first readline/other of shell process that exists before owlsm, will be missed
    Then I dont find the event in output in "10" seconds:
        | process.shell_command    | echo 123 > /tmp/first_readline_missed      |
    # But we should still see the WRITE event for the first command (just without shell_command)
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                      |
        | process.pid              | <shell_pid>                                |
        | process.file.filename    | <shell_file>                               |
        | process.shell_command    |                                            |
        | data.target.file.path    | /tmp/first_readline_missed                 |
    # Second readline of shell process that exists before owlsm, will be seen
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                      |
        | process.pid              | <shell_pid>                                |
        | process.file.filename    | <shell_file>                               |
        | process.shell_command    | echo 456 > /tmp/second_readline_seen       |
        | data.target.file.path    | /tmp/second_readline_seen                  |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: new_shell_gets_detected_and_monitored
    Given I stop the owLSM process
    And The owLSM process is not running
    And I delete the "shell_db_table" table from the owLSM DB
    And I ensure the file "/tmp/new_shell" does not exist
    And I ensure the file "/tmp/<shell_file>" does not exist
    And I run the command "cp -a <shell_path> /tmp/<shell_file>" sync
    And I add the path "/tmp/<shell_file>" to the file db
    And I add the path "/tmp/new_shell" to the file db
    When I start the owLSM process
    And The owLSM process is running

    # First command - /tmp/<shell_file> is new, not yet detected by owlsm. 
    # This command will trigger few events:
    #   - READ of .so files. 
    #   - FILE_CREATE of /tmp/new_shell
    #   - WRITE of /tmp/new_shell
    # The first event will cause the new shell to be detected and monitored.
    # The CREATE_FILE and WRITE events might have "echo 123 > /tmp/new_shell" shell_command, buts its racy.
    # The first event (which is READ of some .so file) will not have shell_command, as this shell isn't monitored yet.
    And I run shell command "echo 123 > /tmp/new_shell" with shell "/tmp/<shell_file>" and save shell pid
    # Wait for owlsm to detect the new shell and hook it with uprobes
    And I sleep for "2" seconds
    # Second command - /tmp/<shell_file> is now monitored
    And I run shell command "echo 456 > /tmp/new_shell" with shell "/tmp/<shell_file>" and save shell pid
    Then I find the event in output in "10" seconds:
        | type                     | READ                                       |
        | process.file.path        | /tmp/<shell_file>                          |
        | process.shell_command    |                                            |
    And I find the event in output in "10" seconds:
        | type                     | WRITE                                      |
        | process.pid              | <shell_pid>                                |
        | process.file.path        | /tmp/<shell_file>                          |
        | process.shell_command    | echo 456 > /tmp/new_shell                  |
        | data.target.file.path    | /tmp/new_shell                             |

    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash | dash      |


Scenario Outline: complex_commands
    Given The owLSM process is running
    And I ensure the file "/tmp/cc_test" does not exist
    And I add the path "/tmp/cc_test" to the file db
    # Run all 20 complex commands on the same shell instance — each combines 4+ shell features
    # Note: pipes and || cannot be tested because | is the Gherkin datatable delimiter
    When I spawn a persistent shell "<shell_path>" and save it
    # 1. external + AND + quotes + semicolon + two redirect types
    And I send command "cat /dev/null && echo 'hello world' > /tmp/cc_test; echo done >> /tmp/cc_test" to the persistent shell
    # 2. negation + stderr redirect + semicolon + quoted special chars + AND
    And I send command "! cat /nonexistent 2> /dev/null; echo 'fallback !@#' > /tmp/cc_test && echo ok >> /tmp/cc_test" to the persistent shell
    # 3. background + semicolons + external + AND + two redirect types
    And I send command "sleep 0.1 & echo bg > /tmp/cc_test; cat /dev/null && echo fg >> /tmp/cc_test" to the persistent shell
    # 4. four semicolons + external + AND + two redirect types
    And I send command "echo s1 > /tmp/cc_test; cat /dev/null; echo s2 >> /tmp/cc_test && echo s3 >> /tmp/cc_test; echo s4 >> /tmp/cc_test" to the persistent shell
    # 5. negation + stderr + AND + quotes + external + semicolons
    And I send command "! cat /nonexistent 2> /dev/null && echo 'neg ok' > /tmp/cc_test; ls /tmp > /dev/null; echo done >> /tmp/cc_test" to the persistent shell
    # 6. two backgrounds + quotes + semicolons + two redirect types
    And I send command "sleep 0.1 & sleep 0.1 & echo 'two bg' > /tmp/cc_test; echo done >> /tmp/cc_test" to the persistent shell
    # 7. semicolons + negation + stderr + AND + quoted special chars + external
    And I send command "echo start > /tmp/cc_test; ! cat /nonexistent 2> /dev/null && echo 'mid !@#' >> /tmp/cc_test; cat /dev/null; echo end >> /tmp/cc_test" to the persistent shell
    # 8. deep AND chain (4 cmds) + externals + quotes + two redirect types
    And I send command "cat /dev/null && echo 'step one' > /tmp/cc_test && ls /tmp > /dev/null && echo 'step two' >> /tmp/cc_test" to the persistent shell
    # 9. background + external + AND + quotes + negation + stderr + semicolons
    And I send command "sleep 0.1 & cat /dev/null && echo 'bg and' > /tmp/cc_test; ! cat /nonexistent 2> /dev/null; echo end >> /tmp/cc_test" to the persistent shell
    # 10. deep chain (6 cmds) + external + AND + two redirect types
    And I send command "echo p1 > /tmp/cc_test; echo p2 >> /tmp/cc_test; echo p3 >> /tmp/cc_test; cat /dev/null && echo p4 >> /tmp/cc_test; ls /tmp > /dev/null; echo p5 >> /tmp/cc_test" to the persistent shell
    # 11. multiple quoted strings + semicolons + AND + external
    And I send command "echo 'line one' > /tmp/cc_test; echo 'line two' >> /tmp/cc_test && cat /dev/null; echo 'line three' >> /tmp/cc_test" to the persistent shell
    # 12. background + negation + stderr + semicolons + quotes
    And I send command "sleep 0.1 & ! cat /nonexistent 2> /dev/null; echo 'result' > /tmp/cc_test && echo done >> /tmp/cc_test" to the persistent shell
    # 13. three quoted strings + two externals + AND + semicolons
    And I send command "echo 'abc def' > /tmp/cc_test; ls /tmp > /dev/null && echo 'ghi jkl' >> /tmp/cc_test; cat /dev/null; echo 'mno pqr' >> /tmp/cc_test" to the persistent shell
    # 14. AND + external + semicolon + background + quoted special chars + AND
    And I send command "echo start > /tmp/cc_test && cat /dev/null; sleep 0.1 & echo 'mid !@#' >> /tmp/cc_test && echo end >> /tmp/cc_test" to the persistent shell
    # 15. six operations + negation + stderr + AND + externals + semicolons
    And I send command "echo r1 > /tmp/cc_test; ls /tmp > /dev/null; cat /dev/null; echo r2 >> /tmp/cc_test && echo r3 >> /tmp/cc_test; ! cat /nonexistent 2> /dev/null; echo r4 >> /tmp/cc_test" to the persistent shell
    # 16. many args + quotes + semicolons + AND + external
    And I send command "echo one two three > /tmp/cc_test; echo 'four five' >> /tmp/cc_test && cat /dev/null; echo six >> /tmp/cc_test; ls /tmp > /dev/null" to the persistent shell
    # 17. background + quotes + semicolons + AND + negation + stderr
    And I send command "sleep 0.1 & echo 'bg start' > /tmp/cc_test; cat /dev/null && ! cat /nonexistent 2> /dev/null; echo 'bg end' >> /tmp/cc_test" to the persistent shell
    # 18. subshell + inner external + outer AND chain
    And I send command "( echo sub1 > /tmp/cc_test; cat /dev/null ); echo outer1 >> /tmp/cc_test && echo outer2 >> /tmp/cc_test" to the persistent shell
    # 19. subshell with inner AND + outer semicolons + external
    And I send command "( echo sa > /tmp/cc_test && echo sb >> /tmp/cc_test ); cat /dev/null; echo sc >> /tmp/cc_test" to the persistent shell
    # 20. subshell + external + outer AND + outer semicolons
    And I send command "( cat /dev/null; echo n1 > /tmp/cc_test ) && echo n2 >> /tmp/cc_test; echo n3 >> /tmp/cc_test" to the persistent shell
    # Verify all 20 commands are found — subshells last (may differ in dash formatting)
    # Note: pipes and || cannot be tested because | is the Gherkin datatable delimiter
    # 1. external + AND + quotes + semicolon
    Then I find the event in output in "30" seconds:
        | parent_process.shell_command    | cat /dev/null && echo 'hello world' > /tmp/cc_test; echo done >> /tmp/cc_test                                                                                    |
    # 2. negation + stderr + semicolon + quoted special chars + AND
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | ! cat /nonexistent 2> /dev/null; echo 'fallback !@#' > /tmp/cc_test && echo ok >> /tmp/cc_test                                                                    |
    # 3. background + semicolons + external + AND
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | sleep 0.1 & echo bg > /tmp/cc_test; cat /dev/null && echo fg >> /tmp/cc_test                                                                                     |
    # 4. four semicolons + external + AND
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo s1 > /tmp/cc_test; cat /dev/null; echo s2 >> /tmp/cc_test && echo s3 >> /tmp/cc_test; echo s4 >> /tmp/cc_test                                                |
    # 5. negation + stderr + AND + quotes + external + semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | ! cat /nonexistent 2> /dev/null && echo 'neg ok' > /tmp/cc_test; ls /tmp > /dev/null; echo done >> /tmp/cc_test                                                   |
    # 6. two backgrounds + quotes + semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | sleep 0.1 & sleep 0.1 & echo 'two bg' > /tmp/cc_test; echo done >> /tmp/cc_test                                                                                  |
    # 7. semicolons + negation + stderr + AND + quoted special chars + external
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo start > /tmp/cc_test; ! cat /nonexistent 2> /dev/null && echo 'mid !@#' >> /tmp/cc_test; cat /dev/null; echo end >> /tmp/cc_test                              |
    # 8. deep AND chain + externals + quotes
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | cat /dev/null && echo 'step one' > /tmp/cc_test && ls /tmp > /dev/null && echo 'step two' >> /tmp/cc_test                                                         |
    # 9. background + external + AND + quotes + negation + stderr + semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | sleep 0.1 & cat /dev/null && echo 'bg and' > /tmp/cc_test; ! cat /nonexistent 2> /dev/null; echo end >> /tmp/cc_test                                               |
    # 10. deep chain (6 cmds) + external + AND
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo p1 > /tmp/cc_test; echo p2 >> /tmp/cc_test; echo p3 >> /tmp/cc_test; cat /dev/null && echo p4 >> /tmp/cc_test; ls /tmp > /dev/null; echo p5 >> /tmp/cc_test   |
    # 11. multiple quoted strings + semicolons + AND + external
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo 'line one' > /tmp/cc_test; echo 'line two' >> /tmp/cc_test && cat /dev/null; echo 'line three' >> /tmp/cc_test                                                |
    # 12. background + negation + stderr + semicolons + quotes + AND
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | sleep 0.1 & ! cat /nonexistent 2> /dev/null; echo 'result' > /tmp/cc_test && echo done >> /tmp/cc_test                                                            |
    # 13. three quoted strings + two externals + AND + semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo 'abc def' > /tmp/cc_test; ls /tmp > /dev/null && echo 'ghi jkl' >> /tmp/cc_test; cat /dev/null; echo 'mno pqr' >> /tmp/cc_test                                |
    # 14. AND + external + semicolon + background + quoted special chars
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo start > /tmp/cc_test && cat /dev/null; sleep 0.1 & echo 'mid !@#' >> /tmp/cc_test && echo end >> /tmp/cc_test                                                |
    # 15. six operations + negation + stderr + AND + externals + semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo r1 > /tmp/cc_test; ls /tmp > /dev/null; cat /dev/null; echo r2 >> /tmp/cc_test && echo r3 >> /tmp/cc_test; ! cat /nonexistent 2> /dev/null; echo r4 >> /tmp/cc_test |
    # 16. many args + quotes + semicolons + AND + external
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | echo one two three > /tmp/cc_test; echo 'four five' >> /tmp/cc_test && cat /dev/null; echo six >> /tmp/cc_test; ls /tmp > /dev/null                                |
    # 17. background + quotes + semicolons + AND + negation + stderr
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | sleep 0.1 & echo 'bg start' > /tmp/cc_test; cat /dev/null && ! cat /nonexistent 2> /dev/null; echo 'bg end' >> /tmp/cc_test                                       |
    # 18. subshell + inner external + outer AND chain
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | ( echo sub1 > /tmp/cc_test; cat /dev/null ); echo outer1 >> /tmp/cc_test && echo outer2 >> /tmp/cc_test                                                            |
    # 19. subshell with inner AND + outer semicolons + external
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | ( echo sa > /tmp/cc_test && echo sb >> /tmp/cc_test ); cat /dev/null; echo sc >> /tmp/cc_test                                                                      |
    # 20. subshell + external + outer AND + outer semicolons
    And I find the event in output in "10" seconds:
        | parent_process.shell_command    | ( cat /dev/null; echo n1 > /tmp/cc_test ) && echo n2 >> /tmp/cc_test; echo n3 >> /tmp/cc_test                                                                      |
    Examples:
        | shell_path | shell_file |
        | /bin/bash  | bash       |
        | /bin/zsh   | zsh        |
        | /bin/dash  | dash       |


Scenario: shell_db_contains_all_system_shells
    Given I stop the owLSM process
    And The owLSM process is not running
    And I delete the "shell_db_table" table from the owLSM DB
    When I start the owLSM process
    And The owLSM process is running
    And I sleep for "5" seconds
    Then all shells from /etc/shells are in the DB with correct data


Scenario: shell_monitoring_disabled
    Given I stop the owLSM process
    And The owLSM process is not running
    And I ensure the file "/tmp/shell_monitoring_disabled_test" does not exist
    When I start the owLSM process with config file "shell_monitoring_disabled_config.json"
    And The owLSM process is running
    And I add the path "/tmp/shell_monitoring_disabled_test" to the file db
    And I run shell command "echo 123 > /tmp/shell_monitoring_disabled_test" with shell "/bin/bash" and save shell pid
    Then I find the event in output in "30" seconds:
        | type                     | WRITE                                     |
        | process.pid              | <shell_pid>                               |
        | process.file.filename    | bash                                      |
        | process.shell_command    |                                           |
        | data.target.file.path    | /tmp/shell_monitoring_disabled_test        |
    And I dont find the event in output in "5" seconds:
        | process.shell_command    | echo 123 > /tmp/shell_monitoring_disabled_test |
    And I dont find the event in output in "5" seconds:
        | parent_process.shell_command    | echo 123 > /tmp/shell_monitoring_disabled_test |
    And I stop the owLSM process
    And The owLSM process is not running
    And I start the owLSM process
    And The owLSM process is running


Scenario: shell_command_blocked_write
    Given The owLSM process is running
    And I ensure new file "/tmp/shell_command_blocking.txt" is created
    And I run the command "chmod 777 /tmp/shell_command_blocking.txt" sync
    And I add the path "/tmp/shell_command_blocking.txt" to the file db
    When I run shell command "echo blocked > /tmp/shell_command_blocking.txt" with shell "/bin/bash" and save shell pid
    And file size of "/tmp/shell_command_blocking.txt" is "0" bytes
    Then I find the event in output in "30" seconds:
        | type                     | WRITE                              |
        | action                   | BLOCK_EVENT                        |
        | process.pid              | <shell_pid>                        |
        | process.file.filename    | bash                               |
        | process.shell_command    | echo blocked > /tmp/shell_command_blocking.txt |
        | data.target.file.path    | /tmp/shell_command_blocking.txt    |
        | matched_rule_id          | 32                                 |
