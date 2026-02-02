import socket
import ssl
import time
import sys
import os
from abc import ABC, abstractmethod
from http.server import HTTPServer, SimpleHTTPRequestHandler
from Utils.process_utils import run_command_async, run_command_sync
import requests
import urllib3
import paramiko
from enum import Enum
import subprocess
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from Utils.logger_utils import logger
from state_db.file_db import file_db
from globals.system_related_globals import system_globals
from Utils.file_utils import *

def generate_temp_ssl_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256())
    
    pem_path = "/tmp/test_ssl.pem"
    recreate_file(pem_path)
    with open(pem_path, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    return pem_path

global_socket = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PROTOCOL(Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    SFTP = "SFTP"
    NETCAT = "NETCAT"
    
    @classmethod
    def from_string(cls, protocol_str):
        try:
            return cls(protocol_str.upper())
        except ValueError:
            raise ValueError(f"Invalid protocol: {protocol_str}")
    
    def to_string(self):
        return self.value


class Base_Test_Server(ABC):
    def __init__(self, port, expected_connection, timeout):
        self.port = port
        self.expected_connection = expected_connection
        self.timeout = timeout
    
    @abstractmethod
    def listen(self):
        pass
        

class Test_HTTP_Server(Base_Test_Server):
    __test__ = False
    request_handled = False

    class IPv6HTTPServer(HTTPServer):
        address_family = socket.AF_INET6
        
    class TrackingHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            logger.log_info(f"[SRV] TrackingHandler initialized")
            Test_HTTP_Server.request_handled = True

        def log_message(self, format, *args):
                pass


    def __init__(self, port, expected_connection, timeout):
        super().__init__(port, expected_connection, timeout)
        Test_HTTP_Server.request_handled = False
        try:
            self.listen()
            if self.expected_connection != Test_HTTP_Server.request_handled:
                error_message = f"[SRV] expected_connection: {self.expected_connection}, request_handled: {Test_HTTP_Server.request_handled}"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)

        except Exception as e:
            error_message = f"[SRV] unexpected error: {e}"
            logger.log_error(error_message)
            system_globals.networking_globals.error_messages.append(error_message)

    def listen(self):
        system_globals.networking_globals.server_object = Test_HTTP_Server.IPv6HTTPServer(('::', self.port), Test_HTTP_Server.TrackingHandler)
        system_globals.networking_globals.server_object.timeout = self.timeout
        logger.log_info(f"[SRV] Started HTTP server on http://[{system_globals.networking_globals.SERVER_IPv6_ADDR}]:{self.port}")
        system_globals.networking_globals.server_object.handle_request()


class Test_HTTPS_Server(Test_HTTP_Server):
    __test__ = False

    def __init__(self, port, expected_connection, timeout):
        super().__init__(port, expected_connection, timeout)
    
    def listen(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        pem_path = generate_temp_ssl_pem()
        context.load_cert_chain(certfile=pem_path, keyfile=pem_path)
        system_globals.networking_globals.server_object = HTTPServer(('0.0.0.0', self.port), Test_HTTP_Server.TrackingHandler)
        system_globals.networking_globals.server_object.socket = context.wrap_socket(system_globals.networking_globals.server_object.socket, server_side=True)
        system_globals.networking_globals.server_object.timeout = self.timeout
        system_globals.networking_globals.server_object.handle_request()


class Test_File_Existence_Server(Base_Test_Server):
    __test__ = False

    def __init__(self, timeout):
        super().__init__(None, None, timeout)
        if os.path.exists(system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE):
            system_globals.networking_globals.error_messages.append(f"[SRV] File {system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE} exists before")
        time.sleep(self.timeout)
        if not os.path.exists(system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE):
            system_globals.networking_globals.error_messages.append(f"[SRV] File {system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE} doesn't exists")

        file_db.add(system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE)

    def listen(self):
        pass


class Test_Netcat_Server(Base_Test_Server):
    __test__ = False

    def __init__(self, port, expected_connection, timeout):
        super().__init__(port, expected_connection, timeout)

        netcat = run_command_async(f"{system_globals.networking_globals.NETCAT_PATH} -l -p {self.port} -w {self.timeout}")
        if netcat is None:
            error_message = f"[SRV] Failed to start netcat server"
            logger.log_error(error_message)
            system_globals.networking_globals.error_messages.append(error_message)
            return

        try:
            stdout, stderr = netcat.communicate(input=system_globals.networking_globals.SERVER_MESSAGE, timeout=self.timeout)
            result = stdout and system_globals.networking_globals.CLIENT_MESSAGE.strip() in stdout.strip()
            if result != self.expected_connection:
                error_message = f"[SRV] expected_connection: {self.expected_connection}, result: {result}\nstdout: {stdout.strip()}\nstderr: {stderr.strip()}"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)
                return
        except subprocess.TimeoutExpired:
            if self.expected_connection:
                error_message = f"[SRV] Netcat server timed out - no connection was established as expected"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)
        finally:
            netcat.kill()
            netcat.wait()


        
    
    def listen(self):
        pass


class Base_Test_Client(ABC):
    def __init__(self, server_port, expected_connection, timeout):
        self.server_port = server_port
        self.expected_connection = expected_connection
        self.timeout = timeout

    def connect(self):
        pass

    def request(self):
        pass


class Test_HTTP_Client(Base_Test_Client):
    __test__ = False

    def __init__(self, server_port, expected_connection, timeout):
        super().__init__(server_port, expected_connection, timeout)

    def connect(self):
        request_handled = False
        status_error_message = None

        try:
            response = self.request()
            
            try:
                response.raise_for_status()
                request_handled = True
            except Exception as e:
                request_handled = False
                status_error_message = f"{e}"

            if self.expected_connection != request_handled:
                error_message = f"[CLIENT] expected_connection: {self.expected_connection}, request_handled: {request_handled}, status_error_message: {status_error_message}"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)

        except requests.exceptions.Timeout as e:
            if self.expected_connection:
                error_message = f"[CLIENT] expected_connection: {self.expected_connection}, request_handled: {request_handled}, status_error_message: {status_error_message}, timeout error: {e}"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)

        except Exception as e:
            error_message = f"[CLIENT] unexpected error: {e}"
            logger.log_error(error_message)
            system_globals.networking_globals.error_messages.append(error_message)

    def request(self):
        return requests.get(f"http://[{system_globals.networking_globals.SERVER_IPv6_ADDR}]:{self.server_port}", timeout=self.timeout)


class Test_HTTPS_Client(Test_HTTP_Client):
    __test__ = False

    def __init__(self, server_port, expected_connection, timeout):
        super().__init__(server_port, expected_connection, timeout)

    def connect(self):
        super().connect()

    def request(self):
        return requests.get(f"https://{system_globals.networking_globals.SERVER_IP_ADDR}:{self.server_port}", timeout=self.timeout, verify=False)


class Test_SSH_Client(Base_Test_Client):
    __test__ = False

    def __init__(self, server_port, expected_connection, timeout):
        super().__init__(server_port, expected_connection, timeout)

    def connect(self):
        request_handled = False
        stdout = None
        stderr = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=system_globals.networking_globals.SERVER_IP_ADDR, port=self.server_port, username=system_globals.USER_NAME, password=system_globals.PASSWORD, timeout=self.timeout)
            logger.log_info(f"[CLIENT] Successfully connected to the SSH server!")

            command = f"touch {system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE}"
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                request_handled = True

            if self.expected_connection != request_handled:
                stderr_output = stderr.read().decode('utf-8').strip() if stderr else "N/A"
                stdout_output = stdout.read().decode('utf-8').strip() if stdout else "N/A"
                error_message = f"[CLIENT] expected_connection: {self.expected_connection}, request_handled: {request_handled}, stderr: {stderr_output}, stdout: {stdout_output}"
                logger.log_error(error_message)
                system_globals.networking_globals.error_messages.append(error_message)

        except Exception as e:
            stderr_output = stderr.read().decode('utf-8').strip() if stderr else "N/A"
            stdout_output = stdout.read().decode('utf-8').strip() if stdout else "N/A"
            error_message = f"[CLIENT] expected_connection: {self.expected_connection}, request_handled: {request_handled}, stderr: {stderr_output}, stdout: {stdout_output} \nunexpected error: {e}"
            logger.log_error(error_message)
            system_globals.networking_globals.error_messages.append(error_message)

        finally:
            if client:
                client.close()


class Test_SFTP_Client(Base_Test_Client):
    __test__ = False

    def __init__(self, server_port, expected_connection, timeout):
        super().__init__(server_port, expected_connection, timeout)
        self.local_file = "/tmp/local_sftp_test_file.txt"
        create_file(self.local_file)

    def connect(self):
        client = None
        session = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=system_globals.networking_globals.SERVER_IP_ADDR, port=self.server_port,
                username=system_globals.USER_NAME,
                password=system_globals.PASSWORD,
                timeout=self.timeout)

            logger.log_info(f"[CLIENT] Successfully connected to the SSH server!")

            session = client.open_sftp()
            session.put(self.local_file, system_globals.networking_globals.FILE_EXISTENCE_FLAG_FILE)
            logger.log_info(f"[CLIENT] SFTP file upload successful!")

        except Exception as e:
            logger.log_error(f"[CLIENT] unexpected error: {e}")
            system_globals.networking_globals.error_messages.append(f"[CLIENT] unexpected error: {e}")

        finally:
            if session:
                session.close()
            if client:
                client.close()


class Test_Netcat_Client(Base_Test_Client):
    __test__ = False
    
    def __init__(self, server_port, expected_connection, timeout):
        super().__init__(server_port, expected_connection, timeout)

    def connect(self):
        run_command_sync(f"ip netns exec {system_globals.networking_globals.NS_NAME} {system_globals.networking_globals.NETCAT_PATH} {system_globals.networking_globals.SERVER_IP_ADDR} {self.server_port} -w {self.timeout} -v -N", timeout=self.timeout + 1, stdin_data=system_globals.networking_globals.CLIENT_MESSAGE + "\n")
    
    def request(self):
        pass


def create_socket(path: str) -> bool:
    try:
        if os.path.exists(path):
            os.remove(path)
        global global_socket
        if global_socket:
            global_socket.close()
        global_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        global_socket.bind(path)
        global_socket.listen(1)
        logger.log_info(f"Successfully created socket: {path}")
        file_db.add(path)
        return True
    except Exception as e:
        logger.log_error(f"Failed to create socket: {path}. Error: {e}")
        return False