"""Smart Home device component of the OSCAHR embedded scenario.

This module contains all methods for the smart home device (server) of the OSCAHR embedded
scenario. To start the smart home device use the file oscahr_smarthomedevice.py, which utilizes
this class.

Version: 0.5.9
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import ipaddress
import logging
import random
import selectors
import socket
import time
import types
import os
import sys
import traceback

# define library locations
script_dir = os.path.dirname(__file__)
project_root = os.path.join(script_dir, '..')
sys.path.append(project_root)

# Local application imports
import common.constant as constant
import common.tor_server as tor
import common.validation as validation


class SmartHomeDevice:
    """Class with all functionalities of the smart home device in the OSCAHR embedded scenario."""

    # Class constants
    _RECEIVE_TIMEOUT = 10  # seconds

    def __init__(self, oscahr_config):
        """Initializes the SmartHomeDecive object with mandatory variables.
        
        Args:
            oscahr_config: An OscahrConfig object initialized for a smart home device in the OSCAHR
                embedded scenario.
        """

        self._log = logging.getLogger()  # get root logger
        self._log.debug("Initializing SmartHomeDevice object...")

        self._config = oscahr_config
        self._config.prepare_oscahr_embedded()

        self._onion_service_dir = self._config.tor_data_dir / "onion_service"
        self._onion_service_address = None
        self._conn_selector = None

    def __enter__(self):
        """Mandatory method for the context manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Mandatory method for the context manager. Calls the method to cleanup the server at
        exit.
        """
        
        self._cleanup_server()

    def start_server(self):
        """Starts a Tor subprocess and the Tor Onion Service (if it exists) and listens for
        connections at the OSCAHR communication port from all local interfaces (including
        connections via the Onion Service).
        """

        self._config.start_tor()

        # Start Tor Onion Service if one exists, if not ignore errors
        try:
            self._onion_service_address = tor.start_disk_v3_onion_service(
                self._onion_service_dir, self._config.tor_control_port, constant.COM_PORT, "192.168.1.1")
        except Exception as error:
            self._log.debug(error)

        self._conn_selector = selectors.DefaultSelector()

        try:
            # Bind to all interfaces on local machine to cover IPv4 and IPv6 addresses and
            # both local client connection and connection from Onion Service to localhost.
            # SO_REUSEADDR flag is automatically set to enable a start of the server a short time
            # period after an previous session (socket is in TIME_WAIT state).
            with socket.create_server(("", constant.COM_PORT), family=socket.AF_INET,
                                      dualstack_ipv6=False) as s:
                self._log.info("Server socket bound to all local interfaces on port "
                               f"{s.getsockname()[1]}, socket is listening...")

                # Handle multiple sockets in this process and therefore allow multiple clients
                s.setblocking(False)

                # Monitor read events (listen for connection)
                self._conn_selector.register(s, selectors.EVENT_READ)

                # Start server forever
                # Exit only with Strg+C by user
                while True:
                    events = self._conn_selector.select(timeout=None)  # Wait forever for events
                    for key, mask in events:
                        if key.data is None:  # New connection -> accept it
                            self._accept_connection(key.fileobj)  # Pass socket object
                        else:  # Established connection -> handle event
                            self._handle_connection_event(key, mask)
        except Exception as error:
            self._log.error(f"Error while starting the server: {error} in {traceback.print_exc()}")

    def _accept_connection(self, sock):
        """Accepts an connection from a given socket and registers it at the selector
        for read and write events.

        Args:
            sock: The socket object to accept a connection from.
        """

        conn, addr = sock.accept()
        conn.setblocking(False)

        # Somehow leads to an error when a normal IPv4 address is given, no idea what is going on, maybe new version
        # If the IP address is a IPv4 mapped IPv6 address unmap it to get a valid IPv4 address
        # if ipaddress.IPv6Address(addr[0]).ipv4_mapped is not None:
        #     ip_address = ipaddress.IPv6Address(addr[0]).ipv4_mapped
        # else:
        #     ip_address = addr[0]
        ip_address = addr[0]

        self._log.info(f"{validation.validate_print_ip_address(ip_address)}:{addr[1]} connected "
                       "to the server")

        # Create object to hold data for this specific socket
        data = types.SimpleNamespace(ip_address=ip_address, port=addr[1], receive_buffer="",
                                     send_buffer="", timer=None)

        # Register this connection and monitor both read and write events
        self._conn_selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=data)

    def _handle_connection_event(self, key, mask):
        """Handles a connection event, proccesses the command if valid and sends the results
        to the client.

        Args:
            key: SelectorKey object of the occured event.
            mask: EventMask of the occured event.
        """

        sock = key.fileobj
        data = key.data
        client_ip_address = data.ip_address
        client_port = data.port

        if mask & selectors.EVENT_READ:
            data.timer = time.time()
            command_raw = sock.recv(128)  # Limit to 128 bytes, all possible commands are smaller
            if command_raw:
                data.receive_buffer += command_raw.decode()
                self._log.debug(f"Received {command_raw}")
            else:
                self._log.info(f"{validation.validate_print_ip_address(client_ip_address)}:"
                               f"{client_port} closed the connection")
                self._conn_selector.unregister(sock)
                sock.close()

        # If the delimiter is in the bytes received until here the command is complete
        # and can be processed
        if constant.DELIMITER_END in data.receive_buffer:
            # Cut at delimiter and discard everything afterwards
            data.receive_buffer = data.receive_buffer.split(constant.DELIMITER_END)[0]

            # Split at delimiter to seperate command and parameter, just one parameter allowed, if
            # there is none partition returns an empty string
            command, _, parameter = data.receive_buffer.partition(constant.DELIMITER_PARAM)
            self._log.info(f"Processing command '{command}' with parameter '{parameter}'")

            data.receive_buffer = ""  # Reset buffer
            data.timer = None  # Reset timer

            # Temperature (random example between -30°C and 40°C)
            if command == constant.LOCAL_COMMANDS[0]:
                data.send_buffer = str(round(random.uniform(-30, 40), 2))

            # Time
            elif command == constant.LOCAL_COMMANDS[1]:
                data.send_buffer = time.strftime("%H:%M:%S", time.localtime())

            # Webinterface
            elif command == constant.LOCAL_COMMANDS[6]:
                # TODO: activate webinterface here
                pass

            # Exit
            elif command == constant.LOCAL_COMMANDS[5]:
                self._log.info(f"{validation.validate_print_ip_address(client_ip_address)}:"
                               f"{client_port} closed the connection")
                self._conn_selector.unregister(sock)
                sock.close()

            # Following commands are only allowed at direct local connection (not via Tor Onion
            # Service; all connections through the Tor network are coming from the Tor Onion
            # Service at localhost - IPv4 address 127.0.0.1)
            elif ipaddress.ip_address(client_ip_address) != ipaddress.IPv4Address("127.0.0.1"):
                # Remote access activation
                if command == constant.LOCAL_COMMANDS[2]:
                    try:
                        # If there is an existing Onion Service, add the client authorization
                        # file and reload the Tor controller, otherwise create a new Onion Service
                        if tor.check_existing_onion_service(self._onion_service_dir):
                            tor.add_disk_v3_onion_service_auth(self._onion_service_dir,
                                                               client_pub_key=parameter)
                            tor.reload_disk_v3_onion_service(self._onion_service_dir,
                                                             self._config.tor_control_port,
                                                             constant.COM_PORT)
                        else:
                            self._onion_service_address = tor.create_disk_v3_onion_service(
                                self._onion_service_dir, self._config.tor_control_port,
                                client_pub_key=parameter, port=constant.COM_PORT)

                        data.send_buffer = self._onion_service_address
                    except Exception as error:
                        data.send_buffer = constant.ERROR_RESPONSE
                        self._log.error(f"Error while creating Tor Onion Service: {error}")

                # Remote access deactivation
                elif command == constant.LOCAL_COMMANDS[3]:
                    try:
                        tor.remove_disk_v3_onion_service_auth(
                            self._onion_service_dir, parameter, self._config.tor_control_port,
                            constant.COM_PORT)

                        data.send_buffer = constant.SUCCESS_RESPONSE
                    except Exception as error:
                        data.send_buffer = constant.ERROR_RESPONSE
                        self._log.error("Error while removing client authorization file: "
                                        f"{error}")

                # Onion service removal
                elif command == constant.LOCAL_COMMANDS[4]:
                    try:
                        tor.remove_disk_v3_onion_service(self._onion_service_dir,
                                                         self._config.tor_control_port)
                        self._onion_service_address = None
                        data.send_buffer = constant.SUCCESS_RESPONSE
                    except Exception as error:
                        data.send_buffer = constant.ERROR_RESPONSE
                        self._log.error(f"Error while removing Tor Onion Service: {error}")

            # Unknown command (empty send buffer and not exit command)
            if data.send_buffer == "" and command != constant.LOCAL_COMMANDS[5]:
                data.send_buffer = constant.ERROR_RESPONSE
                self._log.error(f"Command '{command}' unknown or not allowed")

            # Finally add delimiter to the current send buffer if not empty
            if data.send_buffer != "":
                data.send_buffer += constant.DELIMITER_END

        # If a client sent a command and it doesn't gets completed in the RECEIVE_TIMEOUT timeframe
        # send an error message and reset receive buffer and timer.
        if data.timer is not None and (time.time() - data.timer) > self._RECEIVE_TIMEOUT:
            data.send_buffer = constant.ERROR_RESPONSE + constant.DELIMITER_END
            data.receive_buffer = ""  # Reset buffer
            data.timer = None  # Reset timer
            self._log.warning("No complete command received within the timeout period!")

        if mask & selectors.EVENT_WRITE:
            if data.send_buffer:
                sent = sock.send(data.send_buffer.encode())
                self._log.info(f"Sent '{data.send_buffer[:sent]}' to client "
                               f"{validation.validate_print_ip_address(client_ip_address)}:"
                               f"{client_port}")

                # Remove sent bytes from the send buffer
                data.send_buffer = data.send_buffer[sent:]

    def _cleanup_server(self):
        """Cleans up the server at exit."""

        self._log.debug("Cleaning up server...")
        if self._conn_selector is not None:
            self._conn_selector.close()
