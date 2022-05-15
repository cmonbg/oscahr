"""Smart Home device component of the OSCAHR proxy scenario.

This module contains all methods for the proxy (server) of the OSCAHR proxy scenario. To start the
proxy use the file oscahr_proxy.py, which utilizes this class.

Version: 0.3.2
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import ipaddress
import json
import logging
import selectors
import shutil
import socket
import sys
import os

# define library locations
import time
import traceback
import types

script_dir = os.path.dirname(__file__)
project_root = os.path.join(script_dir, '..')
sys.path.append(project_root)

# Third party imports
import questionary

# Local application imports
import common.prompt as prompt
import common.tor_server as tor
import common.validation as validation
import common.constant as constant



class Proxy:
    """Class with all functionalities of the proxy in the OSCAHR proxy scenario."""

    # Class constants
    _RECEIVE_TIMEOUT = 10  # seconds
    _AUTO_ADD_MODE_STRING = "ANDROID: Start mode for automatic adding with Orbot"
    _NEW_DEVICE_STRING = "Add a new smart home device"
    _REGISTERED_DEVICES_STRING = "Manage registered smart home devices"
    _NEW_CLIENT_STRING = "Add a new client"
    _REGISTERED_CLIENTS_STRING = "Manage registered clients"
    _BACK_TO_MAIN_STRING = "Back to main menu"
    _BACK_TO_DEVICE_STRING = "Back to device menu"
    _BACK_TO_CLIENT_STRING = "Back to client menu"
    _EXIT_STRING = "Exit"
    _CHOICES_REGISTERED_DEVICE = [
        "Manage clients",
        "View IP address and port",
        "Change IP address",
        "Change webinterface port",
        "View Onion address",
        "Rename device",
        "Delete device",
        _BACK_TO_MAIN_STRING
    ]
    _CHOICES_CLIENT = [
        "View public client authorization key",
        "Rename client",
        "Delete client",
        "Back to client menu"
    ]

    def __init__(self, oscahr_config):
        """Initializes the Proxy object with mandatory variables.
        
        Args:
            oscahr_config: An OscahrConfig object initialized for a proxy in the OSCAHR proxy
                scenario.
        """

        self._log = logging.getLogger()  # get root logger
        self._log.debug("Initializing Proxy object...")

        self._config = oscahr_config
        self._config.prepare_oscahr_proxy()

        self._onion_service_main_dir = self._config.tor_data_dir / "onion_services"
        self._registered_devices_file = self._config.oscahr_config_dir / "smarthomedevices.json"

        self._registered_devices = self._get_registered_devices()

    def start_proxy(self):
        """Handles the whole proxy functionality.
        Starts the Tor Onion Service for every registered device and runs forever.
        """

        self._config.start_tor()
        service_counter = 0

        for device in self._registered_devices:
            onion_service_dir = self._onion_service_main_dir / device

            onion_service_address = tor.start_disk_v3_onion_service(
                onion_service_dir, self._config.tor_control_port,
                self._registered_devices[device]["port"],
                self._registered_devices[device]["ip_address"])

            if onion_service_address != self._registered_devices[device]["onion_address"]:
                self._log.warning(f"Tor Onion address for device '{device}' changed, please "
                                  "remove and read it manually!")
            else:
                service_counter += 1

        if service_counter >= 1:
            self._log.info(f"Successfully started {service_counter} Tor Onion Service(s)! Now "
                           "listening forever...")

            # Wait until the Tor subprocess exits, intentionally forever or until Strg+C by user
            self._config.tor_proc.wait()

        else:
            self._log.error("No registered device found! You can add one in management mode "
                            "(-m or --manage). Exiting...")

    def manage_devices(self):
        """Handles the whole functionality for the management mode.
        Starts a menu where new devices can be added and existing devices can be modified.
        """

        # Loop until the main menu is exited or a new device is added
        while True:
            answer_operation = questionary.select(
                "Choose option:",
                choices=[self._NEW_DEVICE_STRING, self._REGISTERED_DEVICES_STRING, self._AUTO_ADD_MODE_STRING,
                         self._EXIT_STRING]).unsafe_ask()

            # Add a new device
            if answer_operation == self._NEW_DEVICE_STRING:
                self._add_device_manually()

            # Registered devices
            elif answer_operation == self._REGISTERED_DEVICES_STRING:
                answer_device = questionary.select(
                    "Choose smart home device:",
                    choices=[*sorted(self._registered_devices.keys()),
                             self._BACK_TO_MAIN_STRING]).unsafe_ask()

                if answer_device == self._BACK_TO_MAIN_STRING:
                    pass  # Main menu gets reopened in while loop
                else:
                    self._manage_registered_devices(answer_device)

            # Automatic adding mode
            elif answer_operation == self._AUTO_ADD_MODE_STRING:
                self.orbot_mode()

            # Exit
            elif answer_operation == self._EXIT_STRING:
                break

    def orbot_mode(self):
        """Starts OSCAHR in Orbot mode, devices can be automatically added from the Orbot app.

        """

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
            command_raw = sock.recv(256)  # Limit to 256 bytes, all possible commands are smaller
            if command_raw:
                data.receive_buffer += command_raw.decode()
                self._log.debug(f"Received {data.receive_buffer}")
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

            # Split at delimiter to separate command and parameter, just one parameter allowed, if
            # there is none partition returns an empty string
            command, _, parameter = data.receive_buffer.partition(constant.DELIMITER_PARAM)
            self._log.info(f"Processing command '{command}' with parameter '{parameter}'")

            data.receive_buffer = ""  # Reset buffer
            data.timer = None  # Reset timer

            # Exit
            if command == constant.LOCAL_COMMANDS[5]:
                self._log.info(f"{validation.validate_print_ip_address(client_ip_address)}:"
                               f"{client_port} closed the connection")
                self._conn_selector.unregister(sock)
                sock.close()

            # Following commands are only allowed at direct local connection (not via Tor Onion
            # Service; all connections through the Tor network are coming from the Tor Onion
            # Service at localhost - IPv4 address 127.0.0.1)
            elif ipaddress.ip_address(client_ip_address) != ipaddress.IPv4Address("127.0.0.1"):
                # Remote access activation

                command = command.split("\\")[1]
                self._log.debug(type(command))
                self._log.debug(command)
                self._log.debug(constant.LOCAL_COMMANDS[2])
                self._log.debug(command == constant.LOCAL_COMMANDS[2])

                if str(command) == constant.LOCAL_COMMANDS[2]:
                    try:
                        self._log.debug("Activating remote access for device")
                        device_info = parameter.split(constant.DELIMITER_PARAM)
                        self._add_device_automatically(*device_info, "orbot")

                        data.send_buffer = self._registered_devices[device_info[0]["onion_address"]]

                        self._log.debug("printing send_buffer: ", data.send_buffer)
                    except Exception as error:
                        data.send_buffer = constant.ERROR_RESPONSE
                        self._log.error(f"Error while creating Tor Onion Service: {error}")

                # TODO
                # Remote access deactivation
                elif command == constant.LOCAL_COMMANDS[3]:
                    try:
                        tor.remove_disk_v3_onion_service_auth(
                            self._onion_service_main_dir, parameter, self._config.tor_control_port,
                            constant.ROUTER_PORT)

                        data.send_buffer = constant.SUCCESS_RESPONSE
                    except Exception as error:
                        data.send_buffer = constant.ERROR_RESPONSE
                        self._log.error("Error while removing client authorization file: "
                                        f"{error} in {traceback.print_exc()}")

                # TODO
                # Onion service removal
                elif command == constant.LOCAL_COMMANDS[4]:
                    try:
                        tor.remove_disk_v3_onion_service(self._onion_service_main_dir,
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
                self._log.debug(data.send_buffer)
                self._log.info(f"Sent '{data.send_buffer[:sent]}' to client "
                               f"{validation.validate_print_ip_address(client_ip_address)}:"
                               f"{client_port}")

                # Remove sent bytes from the send buffer
                data.send_buffer = data.send_buffer[sent:]

    def _add_device_automatically(self, device_name, ip_address, port, public_key, client_name):
        onion_service_dir = self._onion_service_main_dir / device_name

        self._log.info("Adding new smart home device...")

        # Start Tor to be able to create an new Onion Service, afterwards terminate the Tor
        # subprocess (not needed anymore in management mode)
        self._config.start_tor()
        onion_service_address = tor.create_disk_v3_onion_service(
            onion_service_dir, self._config.tor_control_port, public_key, port, ip_address,
            client_name)
        self._config.terminate_tor()

        # Build the dictionary entry for the new device
        new_device = {
            device_name: {
                "ip_address": ip_address,
                "port": port,
                "onion_address": onion_service_address,
                "clients": {
                    client_name: public_key
                }
            }
        }

        # Add the new device to the dictionary and write to JSON file
        self._registered_devices.update(new_device)
        self._set_registered_devices()

    def _add_device_manually(self):
        """Guides the user through the process of adding a new smart home device. Updates the
        registered devices class dictionary and saves the changes to the JSON file.
        """

        device_name = prompt.prompt_device_name(self._registered_devices)
        ip_address = prompt.prompt_ip_address()

        # Stem 1.8.0 doesn't support IPv6 Onion Services yet
        if type(ipaddress.ip_address(ip_address)) is ipaddress.IPv6Address:
            self._log.error("Unfortunately the current stable version of Stem doesn't support "
                            "IPv6 for Onion Services yet! Please use an IPv4 address instead.")
            return

        port = prompt.prompt_port(self._registered_devices, ip_address)
        client_name = prompt.prompt_client_name(self._registered_devices)
        public_key = prompt.prompt_public_key()

        onion_service_dir = self._onion_service_main_dir / device_name

        self._log.info("Adding new smart home device...")

        # Start Tor to be able to create an new Onion Service, afterwards terminate the Tor
        # subprocess (not needed anymore in management mode)
        self._config.start_tor()
        onion_service_address = tor.create_disk_v3_onion_service(
            onion_service_dir, self._config.tor_control_port, public_key, port, ip_address,
            client_name)
        self._config.terminate_tor()

        # Build the dictionary entry for the new device
        new_device = {
            device_name: {
                "ip_address": ip_address,
                "port": port,
                "onion_address": onion_service_address,
                "clients": {
                    client_name: public_key
                }
            }
        }

        # Add the new device to the dictionary and write to JSON file
        self._registered_devices.update(new_device)
        self._set_registered_devices()

        questionary.print(f"Now enter the Tor Onion address '{onion_service_address}' at your "
                          "OSCAHR Client.", style="bold")

        self._log.info(f"Successfully added new smart home device '{device_name}'! To start the "
                       "proxy exit management mode and rerun the program without the mode "
                       "parameter.")

    def _delete_device(self, onion_service_dir, device_name):
        """Deletes the given device including all clients.
        
        Args:
            onion_service_dir: A pathlib object containing the path to the Onion Service to remove.
            device_name: Name of the smart home device to delete as string.
        """

        shutil.rmtree(onion_service_dir)
        self._registered_devices.pop(device_name)
        self._set_registered_devices()

        self._log.info(f"Successfully deleted the device '{device_name}'!")

    def _manage_registered_devices(self, device_name):
        """Guides the user through the process of managing a registered smart home device. If a
        device is modified updates the registered devices class dictionary and saves the changes
        to the JSON file.

        Args:
            device_name: Name of the smart home device to manage as string.
        """

        onion_service_dir = self._onion_service_main_dir / device_name

        # Loop the device menu until exit (back to main menu)
        while True:
            answer_operation = questionary.select(
                f"Choose operation for device '{device_name}':",
                choices=self._CHOICES_REGISTERED_DEVICE).unsafe_ask()

            # Manage clients
            if answer_operation == self._CHOICES_REGISTERED_DEVICE[0]:
                self._manage_clients(onion_service_dir, device_name)

                # If the last client was removed (and therefore the whole device) go back
                # to main menu
                if not tor.check_existing_onion_service_auth(onion_service_dir):
                    break

            # View IP address and port
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[1]:
                ip_address = self._registered_devices[device_name]['ip_address']
                port = self._registered_devices[device_name]['port']
                self._log.info(f"The IP address and port of the device '{device_name}' is "
                               f"{validation.validate_print_ip_address(ip_address)}:{port}")

            # Change IP address
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[2]:
                old_ip_address = self._registered_devices[device_name]["ip_address"]

                ip_address = prompt.prompt_ip_address(
                    self._registered_devices, self._registered_devices[device_name]["port"])

                # Stem 1.8.0 doesn't support IPv6 Onion Services yet
                if type(ipaddress.ip_address(ip_address)) is ipaddress.IPv6Address:
                    self._log.error("Unfortunately the current stable version of Stem doesn't "
                                    "support IPv6 for Onion Services yet! Please use a IPv4 "
                                    "address instead.")
                    continue

                # Update dictionary and write to JSON file
                self._registered_devices[device_name]["ip_address"] = ip_address
                self._set_registered_devices()

                self._log.info(f"Successfully changed IP address of the device '{device_name}' "
                               f"from {validation.validate_print_ip_address(old_ip_address)} to "
                               f"{validation.validate_print_ip_address(ip_address)}")

            # Change webinterface port
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[3]:
                old_port = self._registered_devices[device_name]["port"]

                port = prompt.prompt_port(
                    self._registered_devices, self._registered_devices[device_name]["ip_address"])

                # Update dictionary and write to JSON file
                self._registered_devices[device_name]["port"] = port
                self._set_registered_devices()

                self._log.info("Successfully changed webinterface port of the device "
                               f"'{device_name}' from {old_port} to {port}")

            # View Onion address
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[4]:
                self._log.info(f"The Tor Onion address of the device '{device_name}' is "
                               f"'{self._registered_devices[device_name]['onion_address']}'")

            # Rename device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[5]:
                new_device_name = prompt.prompt_device_name(self._registered_devices)
                new_onion_service_dir = self._onion_service_main_dir / new_device_name

                # Move folder, update dictionary, write to JSON file, update local device
                # name variable and update local Onion Service directory variable
                onion_service_dir.replace(new_onion_service_dir)
                self._registered_devices[new_device_name] = \
                    self._registered_devices.pop(device_name)
                self._set_registered_devices()

                self._log.info(f"Successfully renamed device from '{device_name}' to "
                               f"'{new_device_name}'")

                device_name = new_device_name
                onion_service_dir = self._onion_service_main_dir / device_name

            # Delete device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[6]:
                confirmed = questionary.confirm(
                    "WARNING: After deleting the device at the proxy, all registered clients "
                    "can't access the smart home device through the Tor network anymore! Do you "
                    "want to continue?", default=False).unsafe_ask()

                if confirmed:
                    self._delete_device(onion_service_dir, device_name)
                    break  # Back to main menu

            # Back to main menu
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[7]:
                break

    def _manage_clients(self, onion_service_dir, device_name):
        """Starts a menu where new clients can be added and existing clients can be modified.
        
        Args:
            onion_service_dir: A pathlib object containing the path to the Onion Service.
            device_name: Name of the smart home device to manage as string.
        """

        # Loop the client menu until exit (back to device menu)
        while True:
            answer_operation = questionary.select(
                "Choose option:", choices=[self._NEW_CLIENT_STRING,
                                           self._REGISTERED_CLIENTS_STRING,
                                           self._BACK_TO_DEVICE_STRING]).unsafe_ask()

            # Add a new client
            if answer_operation == self._NEW_CLIENT_STRING:
                client_name = prompt.prompt_client_name(self._registered_devices, device_name)
                public_key = prompt.prompt_public_key()
                self._add_client(device_name, client_name, public_key)

                questionary.print("Now enter the Tor Onion address "
                                  f"'{self._registered_devices[device_name]['onion_address']}' at "
                                  "your OSCAHR Client.", style="bold")

            # Registered clients
            elif answer_operation == self._REGISTERED_CLIENTS_STRING:
                answer_client = questionary.select(
                    "Choose client:",
                    choices=[*sorted(self._registered_devices[device_name]["clients"].keys()),
                             self._BACK_TO_CLIENT_STRING]).unsafe_ask()

                if answer_client == self._BACK_TO_CLIENT_STRING:
                    pass  # Client menu gets reopened in while loop
                else:
                    self._manage_registered_clients(onion_service_dir, device_name, answer_client)

                    # If the last client was removed (and therefore the whole device) go back
                    # to main menu
                    if not tor.check_existing_onion_service_auth(onion_service_dir):
                        break

            # Back to device menu
            elif answer_operation == self._BACK_TO_DEVICE_STRING:
                break

    def _manage_registered_clients(self, onion_service_dir, device_name, client_name):
        """Guides the user through the process of managing the clients of a smart home device. If
        a client is modified updates the registered devices class dictionary and saves the changes
        to the JSON file.

        Args:
            onion_service_dir: A pathlib object containing the path to the Onion Service.
            device_name: Name of the smart home device to manage as string.
            client_name: Name of the client to manage as string.
        """

        # Loop the client menu until exit (back to client main menu)
        while True:
            answer_client_operation = questionary.select(
                f"Choose operation for client '{client_name}':",
                choices=self._CHOICES_CLIENT).unsafe_ask()

            # View public key
            if answer_client_operation == self._CHOICES_CLIENT[0]:
                self._log.info(
                    f"The public client authorization key of the client '{client_name}' is "
                    f"'{self._registered_devices[device_name]['clients'][client_name]}'")

            # Rename client
            elif answer_client_operation == self._CHOICES_CLIENT[1]:
                new_client_name = prompt.prompt_client_name(self._registered_devices, device_name)

                old_onion_service_auth_file = onion_service_dir / tor.AUTH_CLIENT_FOLDER / \
                    (client_name + tor.CLIENT_AUTH_EXTENSION)
                new_onion_service_auth_file = onion_service_dir / tor.AUTH_CLIENT_FOLDER / \
                    (new_client_name + tor.CLIENT_AUTH_EXTENSION)

                # Move client authorization file, update dictionary, write to JSON file and
                # update local device name variable
                old_onion_service_auth_file.replace(new_onion_service_auth_file)
                self._registered_devices[device_name]["clients"][new_client_name] = \
                    self._registered_devices[device_name]["clients"].pop(client_name)
                self._set_registered_devices()

                self._log.info(f"Successfully renamed client from '{client_name}' to "
                               f"'{new_client_name}'")

                client_name = new_client_name

            # Delete client
            elif answer_client_operation == self._CHOICES_CLIENT[2]:
                confirmed = questionary.confirm(
                    "WARNING: After deleting the client at the proxy, the client can't "
                    "access the smart home device through the Tor network anymore! Furthermore if "
                    "this is the last client the whole device gets deleted! "
                    "Do you want to continue?", default=False).unsafe_ask()

                if confirmed:
                    self._delete_client(onion_service_dir, device_name, client_name)
                    break

            # Back to client menu
            elif answer_client_operation == self._CHOICES_CLIENT[3]:
                break

    def _add_client(self, device_name, client_name, public_key):
        """Adds a new client with the given name and public key to the given device.

        Args:
            device_name: Name of the smart home device to add a client to as string.
            client_name: Name of the client to add as string.
            public_key: Public key for the Tor client authorization as string.

        Raises:
            FileNotFoundError: The Onion Service for the given device doesn't exist.
        """

        onion_service_dir = self._onion_service_main_dir / device_name

        if not onion_service_dir.exists():
            raise FileNotFoundError("The Onion Service directory doesn't exist!")
        else:
            tor.add_disk_v3_onion_service_auth(onion_service_dir, public_key, client_name)

            self._registered_devices[device_name]["clients"].update({client_name: public_key})
            self._set_registered_devices()

            self._log.info(f"Successfully added new client '{client_name}' to device "
                           f"'{device_name}'")

    def _delete_client(self, onion_service_dir, device_name, client_name):
        """Deletes the given client from the given device.
        
        Args:
            onion_service_dir: A pathlib object containing the path to the Onion Service.
            device_name: Name of the smart home device to delete a client from as string.
            client_name: Name of the client to delete as string.
        """

        client_file = onion_service_dir / tor.AUTH_CLIENT_FOLDER / \
            (client_name + tor.CLIENT_AUTH_EXTENSION)
        client_file.unlink()

        self._registered_devices[device_name]["clients"].pop(client_name)
        self._set_registered_devices()

        self._log.info(f"Successfully deleted client '{client_name}' from device '{device_name}'")

        # Check if there is another client authorization file otherwise remove whole Onion
        # Service to avoid access without client authorization
        if not tor.check_existing_onion_service_auth(onion_service_dir):
            self._log.debug("Last client authorization file deleted from Onion Service, "
                            "therefore deleting whole device!")
            self._delete_device(onion_service_dir, device_name)

    def _get_registered_devices(self):
        """Reads all registered smart home devices from the JSON file and loads them in a
        dictionary. Validates all values of the dictionary. If one of them is invalid a TypeError
        is raised and the JSON file has to be inspected manually.

        Returns:
            A nested dictionary with the device name as key and the dictionary containing the ip
            address, port, Tor Onion address and the client-dictionary as value.
        
        Raises:
            TypeError: One of the values in the JSON file is invalid (detailed description given).
        """

        registered_devices = dict()

        if self._registered_devices_file.exists():
            registered_devices = json.loads(self._registered_devices_file.read_text())

            # Validate all devices loaded from the JSON file
            values = ["ip_address", "port", "onion_address", "clients"]
            for device_name, device_value in registered_devices.items():
                # Check if all required values are present for the current device
                if values != [*device_value]:
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' doesn't match the required structure!")

                # Validate every value
                if not validation.validate_ip_address(device_value["ip_address"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid IP address!")
                if not validation.validate_port(device_value["port"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid port!")
                if not validation.validate_onion_v3_address(device_value["onion_address"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid Tor Onion address!")

                # Validate every client public key
                for client_name, public_key in device_value["clients"].items():
                    if not validation.validate_base32_key(public_key):
                        raise TypeError(
                            f"The client '{client_name}' of the device '{device_name}' in the JSON"
                            f" file '{self._registered_devices_file}' has an invalid public key!")

        return registered_devices

    def _set_registered_devices(self):
        """Saves the registered devices nested class dictionary in a JSON file in the configured
        filepath.
        """

        self._registered_devices_file.write_text(json.dumps(self._registered_devices))
