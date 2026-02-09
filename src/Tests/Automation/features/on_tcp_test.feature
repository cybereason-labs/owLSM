Feature: On connection tests

Scenario: allowed_http_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "HTTP" connection on port "8000" and connection expected to be "true"
    Then I find the event in output in "20" seconds:
        | process.pid                   | <automation_pid>   |
        | action                        | ALLOW_EVENT        |
        | type                          | NETWORK            |
        | data.network.direction        | INCOMING           |
        | data.network.protocol         | 6                  |
        | data.network.destination_port | 8000               |
        | data.network.ip_type          | 10                 |
        | data.network.destination_ip   | <SERVER_IPv6_ADDR> |
        | data.network.source_ip        | <CLIENT_IPv6_ADDR> |
    Then I find the event in output in "20" seconds:
        | process.pid                   | <automation_pid>   |
        | action                        | ALLOW_EVENT        |
        | type                          | NETWORK            |
        | data.network.direction        | OUTGOING           |
        | data.network.protocol         | 6                  |
        | data.network.destination_port | 8000               |
        | data.network.ip_type          | 10                 |
        | data.network.destination_ip   | <SERVER_IPv6_ADDR> |
        | data.network.source_ip        | <CLIENT_IPv6_ADDR> |
        
        

Scenario: blocked_http_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "HTTP" connection on port "8001" and connection expected to be "false"
    Then I find the event in output in "20" seconds:
        | process.pid                   | <automation_pid>   |
        | action                        | BLOCK_EVENT        |
        | type                          | NETWORK            |
        | data.network.direction        | INCOMING           |
        | data.network.protocol         | 6                  |
        | data.network.destination_port | 8001               |
        | data.network.ip_type          | 10                 |
        | data.network.destination_ip   | <SERVER_IPv6_ADDR> |
        | data.network.source_ip        | <CLIENT_IPv6_ADDR> |
        | matched_rule_id               | 14                 |


Scenario: allowed_https_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "HTTPS" connection on port "8443" and connection expected to be "true"
    Then I find the event in output in "20" seconds:
        | process.pid                   | <automation_pid> |
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | INCOMING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 8443             |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |
    And I find the event in output in "20" seconds:
        | process.pid                   | <automation_pid> |
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | OUTGOING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 8443             |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |



Scenario: allowed_ssh_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "SSH" connection on port "22" and connection expected to be "true"
    Then I find the event in output in "20" seconds:
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | INCOMING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 22               |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |
    And I find the event in output in "20" seconds:
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | OUTGOING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 22               |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |



Scenario: allowed_sftp_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "SFTP" connection on port "22" and connection expected to be "true"
    Then I find the event in output in "20" seconds:
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | INCOMING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 22               |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |
    And I find the event in output in "20" seconds:
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | OUTGOING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 22               |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |



Scenario: allowed_netcat_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "NETCAT" connection on port "1337" and connection expected to be "true"
    Then I find the event in output in "20" seconds:
        | process.ppid                  | <automation_pid> |
        | process.file.path             | <NETCAT_PATH>    |
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | INCOMING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 1337             |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |
    And I find the event in output in "20" seconds:
        | process.ppid                  | <automation_pid> |
        | process.file.path             | <NETCAT_PATH>    |
        | action                        | ALLOW_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | OUTGOING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 1337             |
        | data.network.ip_type          | 2                |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | data.network.source_ip        | <CLIENT_IP_ADDR> |


Scenario: blocked_incoming_netcat_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "NETCAT" connection on port "1338" and connection expected to be "false"
    Then I find the event in output in "20" seconds:
        | process.ppid                  | <automation_pid>   |
        | process.file.path             | <NETCAT_PATH>      |
        | action                        | BLOCK_KILL_PROCESS |
        | type                          | NETWORK            |
        | data.network.direction        | INCOMING           |
        | data.network.protocol         | 6                  |
        | data.network.destination_port | 1338               |
        | data.network.ip_type          | 2                  |
        | data.network.destination_ip   | <SERVER_IP_ADDR>   |
        | data.network.source_ip        | <CLIENT_IP_ADDR>   |
        | matched_rule_id               | 13                 |
    And I find the event in output in "30" seconds:
        | process.ppid      | <automation_pid> |
        | process.file.path | <NETCAT_PATH>    |
        | action            | ALLOW_EVENT      |
        | type              | EXIT             |
        | data.exit_code    | 0                |
        | data.signal       | 9                |


Scenario: blocked_outgoing_netcat_connection
    Given The owLSM process is running
    And I setup the fake network
    When I initiate a "NETCAT" connection on port "1339" and connection expected to be "false"
    Then I find the event in output in "20" seconds:
        | process.ppid                  | <automation_pid> |
        | process.file.path             | <NETCAT_PATH>    |
        | action                        | BLOCK_EVENT      |
        | type                          | NETWORK          |
        | data.network.direction        | OUTGOING         |
        | data.network.protocol         | 6                |
        | data.network.destination_port | 1339             |
        | data.network.source_port      | 0                |
        | data.network.ip_type          | 2                |
        | data.network.source_ip        | 0.0.0.0          |
        | data.network.destination_ip   | <SERVER_IP_ADDR> |
        | matched_rule_id               | 12               |
    And I find the event in output in "30" seconds:
        | process.ppid      | <automation_pid> |
        | process.file.path | <NETCAT_PATH>    |
        | action            | ALLOW_EVENT      |
        | type              | EXIT             |
        | data.exit_code    | 0                |
        | data.signal       | 9                |
