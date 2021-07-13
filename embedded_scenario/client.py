"""Client component of the OSCAHR embedded scenario.

This module contains all methods for the client of the OSCAHR embedded scenario. To start the 
client use the file oscahr_client.py, which utilizes this class.

Version: 0.5.9
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import json
import logging
import socket

# Third party imports
import questionary
import socks  # PySocks

# Local application imports
import common.constant as constant
import common.prompt as prompt
import common.tor_client as tor
import common.validation as validation


class Client:
    """Class with all functionalities of the client in the OSCAHR embedded scenario."""

    # Class constants
    _LOCAL_TIMEOUT = 5  # seconds
    _REMOTE_TIMEOUT = 10  # seconds
    _REMOTE_RETRIES_MAX = 5
    _NEW_DEVICE_STRING = "Add a new smart home device"
    _REGISTERED_DEVICE_STRING = "Choose registered smart home device"
    _BACK_TO_MAIN_STRING = "Back to main menu"
    _EXIT_STRING = "Exit"
    _CHOICES_REGISTERED_DEVICE = [
        "Connect locally",
        "Connect remotely",
        "View local IP address",
        "Change local IP address",
        "Rename device",
        "Delete device",
        _BACK_TO_MAIN_STRING
    ]

    def __init__(self, oscahr_config):
        """Initializes the Client object with mandatory variables.

        Args:
            oscahr_config: An OscahrConfig object initialized for a client in the OSCAHR embedded
                scenario.
        """

        self._log = logging.getLogger()  # get root logger
        self._log.debug("Initializing Client object...")

        self._config = oscahr_config
        self._config.prepare_oscahr_embedded(client=True)

        self._onion_service_auth_dir = self._config.tor_data_dir / "onion_auth"
        self._onion_service_auth_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._registered_devices_file = self._config.oscahr_config_dir / "smarthomedevices.json"

        self._registered_devices = self._get_registered_devices()
        self._added_client_auths = False

    def __enter__(self):
        """Mandatory method for the context manager."""
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Mandatory method for the context manager. Writes a log line and removes all Tor client
        authorization files at exit.
        """

        self._log.debug("Cleaning up client...")
        
        # Delete all client authorization files only if all were added successfully before
        if self._added_client_auths:
            self._delete_registered_clients_auths()

    def start_client(self):
        """Handles the whole client functionality.
        Starts a menu where new devices can be added and registered devices can be chosen.
        """

        self._add_registered_client_auths()
        self._added_client_auths = True

        # Loop until the main menu is exited
        while True:
            answer_operation = questionary.select(
                "Choose option:",
                choices=[self._NEW_DEVICE_STRING, self._REGISTERED_DEVICE_STRING,
                         self._EXIT_STRING]).unsafe_ask()

            # Add a new device
            if answer_operation == self._NEW_DEVICE_STRING:
                device_name = self._add_device()
                # After adding new device, open device submenu
                self._choose_operation(device_name)

            # Registered devices
            elif answer_operation == self._REGISTERED_DEVICE_STRING:
                answer_device = questionary.select(
                    "Choose smart home device:", choices=[*sorted(self._registered_devices.keys()),
                                                          self._BACK_TO_MAIN_STRING]).unsafe_ask()

                if answer_device == self._BACK_TO_MAIN_STRING:
                    pass  # Main menu gets reopened in while loop
                else:
                    self._log.debug(f"Registered smart home device '{answer_device}' was chosen")
                    self._choose_operation(answer_device)

            # Exit
            elif answer_operation == self._EXIT_STRING:
                break

    def _add_device(self):
        """Guides the user through the process of adding a new smart home device. Updates the
        registered devices class-dictionary and saves the changes to the JSON file.

        Returns:
            Name of the added smart home device as string.
        """

        device_name = prompt.prompt_device_name(self._registered_devices)
        ip_address = prompt.prompt_ip_address(self._registered_devices)

        # Build the dictionary entry for the new device
        new_device = {
            device_name: {
                "ip_address": ip_address,
                "onion_address": "",
                "public_key": "",
                "private_key": ""
            }
        }

        # Add the new device to the dictionary and write to JSON file
        self._registered_devices.update(new_device)
        tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

        self._log.info(f"Added new smart home device '{device_name}'")

        return device_name

    def _choose_operation(self, device_name):
        """Starts a menu where an operation for the given registered device can be chosen (local or
        remote connection, view IP, change IP, rename device, delete device). Updates the
        registered devices class dictionary in the case of changes and saves the changes to the
        JSON file.

        Args:
            device_name: Name of the smart home device to choose a operation for as string.
        """

        # Loop the device menu until exit (back to main menu)
        while True:
            # Check if remote access is activated for given device
            remote_access = False if self._registered_devices[device_name]["onion_address"] == "" \
                else True

            answer_operation = questionary.select(
                f"Choose operation for device '{device_name}':",
                choices=self._CHOICES_REGISTERED_DEVICE).unsafe_ask()

            # Connect locally
            if answer_operation == self._CHOICES_REGISTERED_DEVICE[0]:
                self._log.info("Starting client in local mode...")
                self._client_local(device_name)

            # Connect remotely
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[1]:
                if remote_access:
                    self._log.info("Starting client in remote mode...")
                    self._client_remote(device_name)
                else:
                    self._log.warning(f"Remote access isn't activated for device '{device_name}' "
                                      "yet. First activate it via local connection!")
                    continue

            # View IP
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[2]:
                ip_address = self._registered_devices[device_name]['ip_address']
                self._log.info(f"The local IP address of the device '{device_name}' is "
                               f"{validation.validate_print_ip_address(ip_address)}")

            # Change IP
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[3]:
                old_ip_address = self._registered_devices[device_name]["ip_address"]
                new_ip_address = prompt.prompt_ip_address(self._registered_devices)
                self._registered_devices[device_name]["ip_address"] = new_ip_address
                tor.set_registered_devices(self._registered_devices, self._registered_devices_file)
                self._log.info("Successfully changed IP address from "
                               f"'{validation.validate_print_ip_address(old_ip_address)}' to "
                               f"'{validation.validate_print_ip_address(new_ip_address)}'")

            # Rename device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[4]:
                new_device_name = prompt.prompt_device_name(self._registered_devices)

                # If remote access is activated rename the client authorization files
                if remote_access:
                    new_private_client_file = self._onion_service_auth_dir / \
                        (new_device_name + tor.CLIENT_AUTH_EXTENSION)
                    old_private_client_file = self._onion_service_auth_dir / \
                        (device_name + tor.CLIENT_AUTH_EXTENSION)
                    old_private_client_file.replace(new_private_client_file)

                # Update dictionary, write to JSON file and update local device name variable
                self._registered_devices[new_device_name] = \
                    self._registered_devices.pop(device_name)
                tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

                self._log.info(f"Successfully renamed device from '{device_name}' to "
                               f"'{new_device_name}'")

                device_name = new_device_name

            # Delete device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[5]:
                if remote_access:
                    confirmed = questionary.confirm(
                        "WARNING: This client is NOT deleted automatically at the smart home "
                        "device! Consider to deactivate remote access first via local connection. "
                        "Do you want to continue?", default=False).unsafe_ask()
                else:
                    confirmed = questionary.confirm(
                        f"Do you want to delete the smart home device '{device_name}'?",
                        default=False).unsafe_ask()

                if confirmed:
                    if remote_access:
                        tor.delete_onion_service_auth(
                            self._onion_service_auth_dir, device_name,
                            self._registered_devices[device_name]["onion_address"],
                            self._registered_devices[device_name]["private_key"])

                    self._registered_devices.pop(device_name)
                    tor.set_registered_devices(self._registered_devices,
                                               self._registered_devices_file)
                    self._log.info(f"Successfully deleted device '{device_name}'!")
                    break

            # Back to main
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[6]:
                break

    def _client_local(self, device_name):
        """Starts client in local mode.
        Establishes a TCP connection to the saved local IP address, lists the sendable commands and
        waits for an answer from the smart home device after sending one.
        Catches all exceptions which may occur and writes it to error log.

        Args:
            device_name: Name of the smart home device to establish a connection as string.
        """

        ip_address = self._registered_devices[device_name]["ip_address"]
        private_key = None
        public_key = None

        try:
            with socket.create_connection((ip_address, constant.COM_PORT),
                                          timeout=self._LOCAL_TIMEOUT) as s:
                self._log.info(f"Connected to {ip_address}:{constant.COM_PORT}")

                while True:
                    command_text = questionary.select(
                        "Choose command:", choices=constant.LOCAL_COMMANDS_TEXT).unsafe_ask()
                    command = constant.LOCAL_COMMANDS[
                        constant.LOCAL_COMMANDS_TEXT.index(command_text)]

                    # Get Onion address if remote access is activated
                    if self._registered_devices[device_name]["onion_address"] != "":
                        onion_address = self._registered_devices[device_name]["onion_address"]
                    else:
                        onion_address = None

                    # Remote access activation
                    if command == constant.LOCAL_COMMANDS[2]:
                        # If remote access is already activated abort sending a command and
                        # return to command selection
                        if onion_address is not None:
                            self._log.warning(
                                f"Remote access for smart home device '{device_name}' is already "
                                f"activated. The Tor Onion address is '{onion_address}'.")
                            continue
                        else:
                            try:
                                private_key, public_key = tor.generate_keypair()
                                command = command + constant.DELIMITER_PARAM + public_key
                            except TypeError as error:
                                self._log.error(error)
                                continue

                    # Remote access deactivation
                    elif command == constant.LOCAL_COMMANDS[3]:
                        # If remote access isn't activated abort sending a command and
                        # return to command selection
                        if onion_address is None:
                            self._log.error("Remote access isn't activated for smart home device "
                                            f"'{device_name}'!")
                            continue
                        else:
                            command = command + constant.DELIMITER_PARAM + \
                                self._registered_devices[device_name]["public_key"]

                    # Onion service deletion
                    elif command == constant.LOCAL_COMMANDS[4]:
                        confirmed = questionary.confirm(
                            "WARNING: The Tor Onion Service will be completely deleted at the "
                            "smart home device! All registered clients are also deleted and loose "
                            "their remote access to the smart home device and have to be readded "
                            "manually! Do you want to continue?", default=False).unsafe_ask()
                        if not confirmed:
                            continue

                    # Send command, receive and process response, if an error occurs exit
                    if not self._send_receive_process(device_name, command, s, public_key,
                                                      private_key):
                        break

        except socket.timeout:
            self._log.error("Timeout while establishing the connection or receiving the "
                            "answer from the smart home device!")
        except ConnectionRefusedError:
            self._log.error("Connection refused by smart home device!")
        except ConnectionResetError:
            self._log.error("Connection was reset by the smart home device!")
        except Exception as error:
            self._log.error(f"A {type(error).__name__} occured while connecting to the smart home "
                            f"device: {error}")

    def _client_remote(self, device_name, remote_retry=0):
        """Starts client in remote mode.
        Starts a Tor subprocess, connects to the local SOCKS5 Tor socks port, establishes a TCP
        connection to the saved Tor Onion Service address using the saved client authorization
        credentials, lists the sendable commands and waits for an answer from the Onion
        Service after sending one.
        Catches all exceptions which may occur and writes it to error log.

        Args:
            device_name: Name of the smart home device to establish a connection as string.
            remote_retry: Integer to indicate the current number of retries for the remote
                connection (maximum is defined in class constant REMOTE_RETRIES_MAX).
        """

        self._config.start_tor(self._onion_service_auth_dir)
        onion_address = self._registered_devices[device_name]["onion_address"]

        try:
            with socks.create_connection(
                    dest_pair=(onion_address, constant.COM_PORT),
                    timeout=self._REMOTE_TIMEOUT,
                    proxy_type=socks.SOCKS5,
                    proxy_addr="127.0.0.1",
                    proxy_port=self._config.tor_socks_port) as s:
                self._log.debug(f"Connected to Tor Onion Service at '{onion_address}'")

                while True:
                    command_text = questionary.select("Choose command:",
                                                      choices=constant.REMOTE_COMMANDS_TEXT
                                                      ).unsafe_ask()
                    command = constant.REMOTE_COMMANDS[
                        constant.REMOTE_COMMANDS_TEXT.index(command_text)]

                    # Send command, receive and process response, if an error occurs exit
                    if not self._send_receive_process(device_name, command, s):
                        break

        except socks.ProxyConnectionError as error:
            self._log.error(f"Unable to connect to local Tor proxy: {error}")
        except socks.GeneralProxyError as error:
            if str(error.socket_err) == "timed out":
                if remote_retry < self._REMOTE_RETRIES_MAX:
                    self._log.warning("Timeout while establishing the connection! Retrying... "
                                      f"({remote_retry + 1}/{self._REMOTE_RETRIES_MAX})")
                    self._config.terminate_tor()
                    self._client_remote(device_name, remote_retry + 1)
                else:
                    self._log.error("Timeout while establishing the connection!")
            else:
                self._log.error(f"Unable to connect to Tor Onion Service: {error}")
        except socket.timeout:
            # PySocks throws socket.timeout error if connection was established but an timeout
            # occurs e.g. while receiving
            self._log.error("Timeout while receiving the answer from the smart home device!")
        except Exception as error:
            self._log.error(f"A {type(error).__name__} occured while connecting to the smart home "
                            f"device: {error}")
        finally:
            self._config.terminate_tor()

    def _send_receive_process(self, device_name, command, socket, public_key=None,
                              private_key=None):
        """Sends the given command, receives the response from the smart home device and processes
        it. Requires the device name, command, socket object and in local mode private and
        public key if the remote access was activated.

        Args:
            device_name: Name of the smart home device to send and receive messages as string.
            command: Command to send to the smart home device as string.
            socket: Socket object to use for sending the command.
            public_key: Optional; Public key for the Tor client authorization as string if remote
                access was activated.
            private_key: Optional; Private key for the Tor client authorization as string if remote
                access was activated.

        Returns:
            True on success, False on failure or exit.
        """

        # Add delimiter and send encoded command
        socket.sendall((command + constant.DELIMITER_END).encode())
        self._log.debug(f"Sent command '{command + constant.DELIMITER_END}' to smart home device")

        if command == constant.LOCAL_COMMANDS[5]:  # Exit
            return False
        else:
            receive_buffer = ""
            # While the delimiter is not in the bytes received keep receiving
            while constant.DELIMITER_END not in receive_buffer:
                # Limit to 64 bytes, all possible responses are smaller
                response_raw = socket.recv(64)

                if response_raw:
                    receive_buffer += response_raw.decode()
                    self._log.debug(f"Received '{response_raw}'")
                else:
                    self._log.info(f"Smart home device '{device_name}' closed the connection")
                    return False

            # If the delimiter is in the bytes received (after while above) the command is complete
            # and can be processed.
            # Cut at delimiter and discard everything afterwards
            response = receive_buffer.split(constant.DELIMITER_END)[0]
            self._log.debug(f"Received response '{response}'")

            if response == constant.ERROR_RESPONSE:
                self._log.error("There was an error at the smart home device!")
            else:
                # Temperature
                if command == constant.LOCAL_COMMANDS[0]:
                    self._log.info(f"Current temperature is {response}°C")

                # Time
                elif command == constant.LOCAL_COMMANDS[1]:
                    self._log.info(f"Current time is {response}")

                # Remote access activation
                elif command.split(constant.DELIMITER_PARAM)[0] == constant.LOCAL_COMMANDS[2]:
                    onion_address = response

                    # Tor doesn't support two client authorization files with the same Onion 
                    # address, therefore check if a device with the received Onion address already
                    # exists (happens when a device has different IP addresses or e.g. an IPv4 and
                    # IPv6 address and both are registered). If a duplicate was found automatically
                    # send the command to deactivate the remote access to the smart home device and
                    # return.
                    for device in self._registered_devices.keys():
                        if onion_address == self._registered_devices[device]["onion_address"]:
                            self._log.warning(
                                f"Onion address '{onion_address}' is already registered for device"
                                f" '{device}', please use the existing device instead! Reverting "
                                "remote access activation at smart home device...")

                            return self._send_receive_process(
                                device_name,
                                constant.LOCAL_COMMANDS[3] + constant.DELIMITER_PARAM + public_key,
                                socket)

                    # If no duplicate was found also activate the remote access locally
                    self._activate_remote_access(device_name, onion_address, public_key, private_key)

                # Remote access deactivation
                elif command.split(constant.DELIMITER_PARAM)[0] == constant.LOCAL_COMMANDS[3]:
                    if response == constant.SUCCESS_RESPONSE:
                        self._deactivate_remote_access(device_name)

                # Onion Service deletion
                elif command == constant.LOCAL_COMMANDS[4]:
                    if response == constant.SUCCESS_RESPONSE:
                        # If remote access was activated also delete local authorization files
                        if self._registered_devices[device_name]["onion_address"] != "":
                            self._deactivate_remote_access(device_name)
                        self._log.info("Successfully deleted Tor Onion Service")

        return True

    def _activate_remote_access(self, device_name, onion_address, public_key, private_key):
        """Activates remote access for the given device to the given Onion address with the given
        public and private key. Adds an authorization file for the device, updates the registered
        devices class-dictionary and writes it to the JSON file.
        Catches all exceptions which may occur and writes it to error log.

        Args:
            device_name: Name of the smart home device to activate remote access for as string.
            onion_address: Tor Onion address of the smart home device as string.
            public_key: Public key for the Tor client authorization as string.
            private_key: Private key for the Tor client authorization as string.
        """

        try:
            tor.add_onion_service_auth(self._onion_service_auth_dir, device_name, onion_address,
                                       private_key)
            self._registered_devices[device_name]["onion_address"] = onion_address
            self._registered_devices[device_name]["public_key"] = public_key
            self._registered_devices[device_name]["private_key"] = private_key
            tor.set_registered_devices(self._registered_devices, self._registered_devices_file)
            self._log.info(f"Successfully activated remote access for device '{device_name}'")
        except Exception as error:
            self._log.error(f"Error while activating remote access for device '{device_name}': "
                            f"{error}")

    def _deactivate_remote_access(self, device_name):
        """Deactivates remote access for the given device. Deletes the authorization file for the
        device, updates the registered devices class-dictionary and writes it to the JSON file.
        Catches all exceptions which may occur and writes it to error log.

        Args:
            device_name: Name of the smart home device to deactivate remote access for as string.
        """

        try:
            tor.delete_onion_service_auth(self._onion_service_auth_dir, device_name,
                                          self._registered_devices[device_name]["onion_address"],
                                          self._registered_devices[device_name]["private_key"])
            self._registered_devices[device_name]["onion_address"] = ""
            self._registered_devices[device_name]["public_key"] = ""
            self._registered_devices[device_name]["private_key"] = ""
            tor.set_registered_devices(self._registered_devices, self._registered_devices_file)
            self._log.info(f"Successfully deactivated remote access for device '{device_name}'")
        except Exception as error:
            self._log.error(f"Error while deactivating remote access for device '{device_name}': "
                            f"{error}")

    def _get_registered_devices(self):
        """Reads all registered smart home devices from the JSON file and loads them in a
        dictionary. Validates all values of the dictionary. If one of them is invalid a TypeError
        is raised and the JSON file has to be inspected manually. The IP address is a mandatory
        value, all other values can also be an empty string (remote access not activated).
        
        Returns:
            A nested dictionary with the device name as key and the dictionary containing the IP
            address, Onion address, public key and private key as value.

        Raises:
            TypeError: One of the values in the JSON file is invalid (detailed description given).
        """

        registered_devices = dict()

        if self._registered_devices_file.exists():
            registered_devices = json.loads(self._registered_devices_file.read_text())

            # Validate all devices loaded from the JSON file
            values = ["ip_address", "onion_address", "public_key", "private_key"]
            onion_addresses = list()
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
                if device_value["onion_address"] != "" and \
                        not validation.validate_onion_v3_address(device_value["onion_address"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid Tor Onion address!")
                if device_value["public_key"] != "" and \
                        not validation.validate_base32_key(device_value["public_key"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid public key!")
                if device_value["private_key"] != "" and \
                        not validation.validate_base32_key(device_value["private_key"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid private key!")

                # Check for Onion address duplicates
                if device_value["onion_address"] in onion_addresses:
                    raise TypeError(f"The Tor Onion address '{device_value['onion_address']}' is "
                                    "registered for multiple devices!")
                elif device_value["onion_address"] != "":
                    onion_addresses.append(device_value["onion_address"])

        return registered_devices

    def _add_registered_client_auths(self):
        """Adds the client authorization file for all registered clients with activated remote
        access.
        """

        for device_name, device_value in self._registered_devices.items():
            if device_value["onion_address"] != "":
                tor.add_onion_service_auth(self._onion_service_auth_dir, device_name,
                                           device_value["onion_address"], device_value["private_key"])

    def _delete_registered_clients_auths(self):
        """Deletes the client authorization file for all registered clients with activated remote
        access.
        """

        for device_name, device_value in self._registered_devices.items():
            if device_value["onion_address"] != "":
                try:
                    tor.delete_onion_service_auth(self._onion_service_auth_dir, device_name,
                                                  device_value["onion_address"],
                                                  device_value["private_key"])
                except Exception as error:
                    self._log.error(f"Error while deleting the client authorization file for "
                                    f"device '{device_name}': {error}")
