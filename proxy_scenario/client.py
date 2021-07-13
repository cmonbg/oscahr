"""Client component of the OSCAHR proxy scenario.

This module contains all methods for the client of the OSCAHR proxy scenario. To start the 
client use the file oscahr_client.py, which utilizes this class.

Version: 0.3.2
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import json
import logging
import os
import pathlib
import platform
import shutil
import subprocess

# Third party imports
import psutil
import questionary

# Local application imports
import common.prompt as prompt
import common.tor_client as tor
import common.validation as validation


class Client:
    """Class with all functionalities of the client in the OSCAHR proxy scenario."""

    # Class constants
    _BACK_TO_MAIN_STRING = "Back to main menu"
    _CHOICES_MAIN_MENU = [
        "Add a new smart home device",
        "Choose registered smart home device",
        "Change Tor Browser directory",
        "Exit and remove the client authorization files",
        "Exit and keep the client authorization files"
    ]
    _CHOICES_REGISTERED_DEVICE = [
        "Start Tor Browser and open device Onion address",
        "View Onion address and port of the device",
        "View public client authorization key",
        "Change webinterface port",
        "Change HTTP/HTTPS usage",
        "Rename device",
        "Delete device",
        _BACK_TO_MAIN_STRING
    ]

    def __init__(self, oscahr_config):
        """Initializes the Client object with mandatory variables.

        Args:
            oscahr_config: An OscahrConfig object initialized for a client in the OSCAHR proxy
                scenario.
        """

        self._log = logging.getLogger()  # get root logger
        self._log.debug("Initializing Client object...")

        self._config = oscahr_config
        self._config.prepare_oscahr_proxy(client=True)

        self._registered_devices_file = self._config.oscahr_config_dir / "smarthomedevices.json"

        (self._torbrowser_base_dir,
         self._torbrowser_startup,
         self._torbrowser_auth_dir) = self._get_torbrowser_paths()
        self._registered_devices = self._get_registered_devices()

    def start_client(self):
        """Handles the whole client functionality.
        Starts a menu where new devices can be added and registered devices can be chosen.
        """

        self._add_registered_client_auths()

        # Loop until the main menu is exited
        while True:
            answer_operation = questionary.select(
                "Choose option:", choices=self._CHOICES_MAIN_MENU).unsafe_ask()

            # Add a new device
            if answer_operation == self._CHOICES_MAIN_MENU[0]:
                device_name = self._add_device()
                # After adding new device, open device submenu
                self._manage_registered_device(device_name)

            # Registered devices
            elif answer_operation == self._CHOICES_MAIN_MENU[1]:
                answer_device = questionary.select(
                    "Choose smart home device:", choices=[*sorted(self._registered_devices.keys()),
                                                          self._BACK_TO_MAIN_STRING]).unsafe_ask()

                if answer_device == self._BACK_TO_MAIN_STRING:
                    pass  # Main menu gets reopened in while loop
                else:
                    self._log.debug(f"Registered smart home device '{answer_device}' was chosen")
                    self._manage_registered_device(answer_device)

            # Change Tor Browser directory
            elif answer_operation == self._CHOICES_MAIN_MENU[2]:
                old_torbrowser_base_dir = self._torbrowser_base_dir
                (self._torbrowser_base_dir,
                 self._torbrowser_startup,
                 self._torbrowser_auth_dir) = self._get_torbrowser_paths(force_manual=True)
                self._log.info("Successfully changed Tor Browser directory from "
                               f"'{old_torbrowser_base_dir}' to '{self._torbrowser_base_dir}'")

            # Exit and remove the client authorization files
            elif answer_operation == self._CHOICES_MAIN_MENU[3]:
                self._delete_registered_clients_auths()
                break

            # Exit and remove the client authorization files
            elif answer_operation == self._CHOICES_MAIN_MENU[4]:
                break

    def _add_device(self):
        """Guides the user through the process of adding a new smart home device. Updates the
        registered devices class-dictionary and saves the changes to the JSON file.

        Returns:
            Name of the added smart home device as string.
        """

        device_name = prompt.prompt_device_name(self._registered_devices)
        private_key, public_key = tor.generate_keypair()

        questionary.print(f"Now enter the public key '{public_key}' at your OSCAHR Proxy.",
                          style="bold")

        onion_address = prompt.prompt_onion_address(self._registered_devices)
        port = prompt.prompt_port()
        https = prompt.prompt_https()

        # Build the dictionary entry for the new device
        new_device = {
            device_name: {
                "onion_address": onion_address,
                "port": port,
                "https": https,
                "public_key": public_key,
                "private_key": private_key
            }
        }

        # Add an authorization file for the new device, update added client auths list,
        # update dictionary and write to JSON file
        self._add_onion_service_auth(device_name, onion_address, private_key)
        self._registered_devices.update(new_device)
        tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

        self._log.info(f"Added new smart home device '{device_name}'")

        return device_name

    def _manage_registered_device(self, device_name):
        """Starts a menu where an operation for the given registered device can be chosen (start
        Tor Browser, view Onion address, view public key, change port, change http/https, rename
        device, delete device). Updates the registered devices class dictionary in the case of
        changes and saves the changes to the JSON file.

        Args:
            device_name: Name of the smart home device to manage as string.
        """

        # Loop the device menu until exit (back to main menu)
        while True:
            onion_address = self._registered_devices[device_name]["onion_address"]
            port = self._registered_devices[device_name]["port"]
            public_key = self._registered_devices[device_name]["public_key"]
            http = "https" if self._registered_devices[device_name]["https"] else "http"
            private_client_file = self._torbrowser_auth_dir / \
                (device_name + tor.CLIENT_AUTH_EXTENSION)

            if not private_client_file.exists():
                raise FileNotFoundError(f"Client authorization file for device '{device_name}' "
                                        "doesn't exist, please restart the client try again!")

            answer_operation = questionary.select(
                f"Choose operation for device '{device_name}':",
                choices=self._CHOICES_REGISTERED_DEVICE).unsafe_ask()

            # Start Tor Browser
            if answer_operation == self._CHOICES_REGISTERED_DEVICE[0]:
                self._start_torbrowser(onion_address, port, http)

            # View Onion address and port
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[1]:
                self._log.info(f"The Tor Onion address and port of the device '{device_name}' is "
                               f"'{http}://{onion_address}:{port}'")

            # View public key
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[2]:
                self._log.info("The public client authorization key of the device "
                               f"'{device_name}' is '{public_key}'")

            # Change port
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[3]:
                old_port = port
                port = prompt.prompt_port()

                # Update dictionary and write to JSON file
                self._registered_devices[device_name]["port"] = port
                tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

                self._log.info("Successfully changed webinterface port of the device "
                               f"'{device_name}' from {old_port} to {port}")

            # Change HTTP/HTTPS
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[4]:
                old_https = self._registered_devices[device_name]["https"]
                https = prompt.prompt_https()

                # Update dictionary and write to JSON file
                self._registered_devices[device_name]["https"] = https
                tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

                self._log.info("Successfully changed the usage of HTTPS of the device "
                               f"'{device_name}' from {old_https} to {https}")

            # Rename device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[5]:
                new_device_name = prompt.prompt_device_name(self._registered_devices)
                new_private_client_file = self._torbrowser_auth_dir / \
                    (new_device_name + tor.CLIENT_AUTH_EXTENSION)

                # Move client authorization file, update added client auths list,
                # update dictionary, write to JSON file and update local device name variable
                private_client_file.replace(new_private_client_file)
                self._registered_devices[new_device_name] = \
                    self._registered_devices.pop(device_name)
                tor.set_registered_devices(self._registered_devices, self._registered_devices_file)

                self._log.info(f"Successfully renamed device from '{device_name}' to "
                               f"'{new_device_name}'")

                device_name = new_device_name

            # Delete device
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[6]:
                confirmed = questionary.confirm(
                    "WARNING: After deleting the smart home device, you can't access it through "
                    "the Tor network anymore with this client! Ensure to delete this client at "
                    "the OSCAHR proxy too! Do you want to continue?", default=False).unsafe_ask()

                if confirmed:
                    tor.delete_onion_service_auth(
                        self._torbrowser_auth_dir, device_name, onion_address,
                        self._registered_devices[device_name]["private_key"])
                    self._registered_devices.pop(device_name)
                    tor.set_registered_devices(self._registered_devices,
                                               self._registered_devices_file)
                    self._log.info(f"Successfully removed device '{device_name}'!")
                    break

            # Back to main
            elif answer_operation == self._CHOICES_REGISTERED_DEVICE[7]:
                break

    def _add_onion_service_auth(self, device_name, onion_address, private_key):
        """Add a new client authorization file for the given device. First checks if the Tor
        Browser is running and asks the user to close it.

        Args:
            device_name: Name of the smart home device to add a client authorization for as string.
            onion_address: Onion address of the Tor Onion Service at the OSCAHR proxy as string.
            private_key: Private key for the Tor client authorization as string.

        Raises:
            RuntimeError: Tor Browser is running and the user decided to exit.
        """

        while self._check_torbrowser_running():
            answer_running = questionary.confirm("Tor Browser is running, please close it "
                                                 "first! To proceed after closing the Tor "
                                                 "Browser type Y, to exit type N").unsafe_ask()
            if not answer_running:
                raise RuntimeError("Tor Browser is running, couldn't add new client "
                                   "authorization file!")

        tor.add_onion_service_auth(self._torbrowser_auth_dir, device_name, onion_address,
                                   private_key)

    def _check_torbrowser_running(self):
        """Checks if the Tor Browser is running.
        
        Returns:
            True if the Tor Browser is running, False if not.
        """

        # The Firefox binary in the Tor Browser Bundle is located in the base dir with the name
        # "firefox.real"/"firefox.exe"
        if os.name != 'nt':
            tor_firefox_binary = self._torbrowser_base_dir / "firefox.real"
        else:
            tor_firefox_binary = self._torbrowser_base_dir / "firefox.exe"

        for proc in psutil.process_iter():
            try:
                if str(tor_firefox_binary) in proc.exe():
                    return True
            # Ignore if the process exited between the interation and the proc.exe() call or
            # the access for calling proc.exe() for the current process was denied
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        return False

    def _start_torbrowser(self, onion_address, port, http):
        """Starts the Tor Browser via the startup script if it isn't running already.
        Opens the given Tor Onion address with the given port using the given hypertext transfer
        protocol.

        Args:
            onion_address: Onion address of the Onion Service to access as string.
            port: Integer port number to use for the Onion Service.
            http: "http" or "https" as string.
        """

        if self._check_torbrowser_running():
            self._log.warning("Tor Browser is already running, please open the Tor Onion address "
                              f"({http}://{onion_address}:{port}) of the smart home device "
                              "manually!")
        else:
            # Start a subprocess to start the Tor Browser detached from the terminal/subprocess
            # and open the Onion-address:port of the smart home device.
            subprocess.Popen(
                [self._torbrowser_startup, http + "://" + onion_address + ":" + str(port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

    def _get_torbrowser_paths(self, force_manual=False):
        """Gets the base path for the Tor Browser, the path for the Tor Browser startup script
        and the path for the client authorization files directory.
        First tries to read Tor Browser base directory from previously saved file, afterwards
        search for installed 'torbrowser-launcher' package on non Windows systems (gets paths
        fully automated). If both previous attempts failed the Tor Browser base directory can be
        manually entered by the user. If the path was entered manually finally asks the user to
        save the base directory to a file for future use.

        Args:
            force_manual: Optional; Boolean to force the use of manual mode. Default is False.
        
        Returns:
            Tor Browser pathlib objects to the base directory, the startup script and the client
            authorization files directory in a tuple.
        
        Raises:
            FileNotFoundError: Tor Browser directory or one of the mandatory files wasn't found.
        """

        torbrowserpath_file = self._config.oscahr_config_dir / "torbrowser.path"
        windows = True if os.name == 'nt' else False
        torbrowser_base_dir = None
        manual_mode = False

        # Read from previously saved file
        if not force_manual and torbrowserpath_file.exists():
            temp_torbrowser_dir = pathlib.Path(torbrowserpath_file.read_text().strip())
            if temp_torbrowser_dir.exists():
                torbrowser_base_dir = temp_torbrowser_dir
                self._log.debug(f"Found Tor Browser base directory at '{torbrowser_base_dir}' "
                                "through previously saved file")
            else:
                self._log.warning("Previously saved Tor Browser directory doesn't exist anymore! "
                                  "Proceeding with normal process of getting directory...")

        # On non Windows systems look for torbrowser-launcher package if Tor Browser directory
        # wasn't found in previously saved file and manual mode wasn't forced
        if not force_manual and torbrowser_base_dir is None and not windows:
            torbrowser_launcher = shutil.which("torbrowser-launcher")

            if torbrowser_launcher is not None:
                # Build path to torrc and Tor Browser binary following the torbrowser-launcher
                # source: https://github.com/micahflee/torbrowser-launcher/blob/master/torbrowser_launcher/common.py
                architecture = "x86_64" if "64" in platform.architecture()[0] else "i686"

                temp_torbrowser_dir = pathlib.Path.home() / ".local" / "share" / "torbrowser" / \
                    "tbb" / architecture

                if not temp_torbrowser_dir.exists():
                    self._log.warning(
                        "Found installed package 'torbrowser-launcher' but the Tor Browser folder "
                        f"in '{temp_torbrowser_dir}' doesn't exist. If the 'torbrowser-launcher' "
                        "package is newly installed, please start the Tor Browser manually the "
                        "first time and try again.")
                else:
                    # The directory starts with "tor-browser_" followed by the installed language
                    # (e.g. "en-US"). Lookup the directory built so far for any installed Tor
                    # Browser language.
                    dir_language = list(temp_torbrowser_dir.glob("tor-browser_*"))

                    if len(dir_language) == 1:
                        torbrowser_base_dir = dir_language[0] / "Browser"
                        self._log.debug(f"Got Tor Browser directory '{torbrowser_base_dir}' "
                                        "through 'torbrowser-launcher' package")
                    else:
                        self._log.warning(
                            "Tor Browser directory tried to find via the 'torbrowser-launcher' "
                            "package wasn't distinct, proceeding with manual input...")
            else:
                self._log.info("OSCAHR couldn't find your Tor Browser automatically. Please "
                               "install it through the debian package 'torbrowser-launcher' or "
                               "download it manually from https://www.torproject.org/.")

        # If both previous attempts failed or manual mode was forced
        if torbrowser_base_dir is None:
            manual_mode = True
            if not windows:
                temp_torbrowser_dir = pathlib.Path.expanduser(pathlib.Path(questionary.path(
                    "Please enter the root directory of your manually installed Tor Browser "
                    "(usually in this directory a file named 'start-tor-browser.desktop' and a "
                    "directory named 'Browser' is located):",
                    validate=lambda text: pathlib.Path.expanduser(pathlib.Path(text)).exists(),
                    only_directories=True
                ).unsafe_ask()))
            else:
                temp_torbrowser_dir = pathlib.Path.expanduser(pathlib.Path(questionary.path(
                    "Please enter the root directory of your Tor Browser (usually in this "
                    "directory a shortcut file named 'Start Tor Browser' and a directory named "
                    "'Browser' is located):",
                    validate=lambda text: pathlib.Path.expanduser(pathlib.Path(text)).exists(),
                    only_directories=True
                ).unsafe_ask()))

            torbrowser_base_dir = temp_torbrowser_dir / "Browser"
            self._log.debug(f"Got Tor Browser base directory at '{torbrowser_base_dir}' through "
                            "manual input")

        # For all modes (saved file, auto and manual) build the startup and torrc path and check
        # if all paths exist
        torbrowser_torrc = torbrowser_base_dir / "TorBrowser" / "Data" / "Tor" / "torrc"

        if not windows:
            torbrowser_startup = torbrowser_base_dir / "start-tor-browser"
        else:
            torbrowser_startup = torbrowser_base_dir / "firefox.exe"

        if not torbrowser_base_dir.exists() or \
                not torbrowser_startup.exists() or \
                not torbrowser_torrc.exists():
            raise FileNotFoundError("Tor Browser directory or one of the mandatory files not "
                                    "found!")
        else:
            self._log.debug(f"Found Tor Browser torrc file at '{torbrowser_torrc}'")
            self._log.debug(f"Found Tor Browser startup file at '{torbrowser_startup}'")

            torbrowser_auth_dir = self._get_torbrowser_auth_dir(torbrowser_torrc)

            # If the Tor Browser directory was entered manually, offer to save it
            if manual_mode:
                save = questionary.confirm(
                    f"Do you want to save the Tor Browser directory '{torbrowser_base_dir}' for "
                    "future use of OSCAHR?").unsafe_ask()
                if save:
                    torbrowserpath_file.write_text(str(torbrowser_base_dir))

            return torbrowser_base_dir, torbrowser_startup, torbrowser_auth_dir

    def _get_torbrowser_auth_dir(self, torbrowser_torrc):
        """Reads the given torrc file and extracts the configured ClientOnionAuthDir. If no
        ClientOnionAuthDir is configured a directory is created and added to the torrc file.

        Args:
            torbrowser_torrc: A pathlib object containing the path to the Tor configuration file.
        
        Returns:
            A pathlib object containing the path to the client onion authorization directory.
        
        Raises:
            FileNotFoundError: A ClientOnionAuthDir is specified in the torrc file but it doesn't
                exist.
        """

        auth_line = None

        with open(torbrowser_torrc, "r") as f:
            for line in f:
                if line.startswith("ClientOnionAuthDir"):
                    auth_line = line.strip()
                    break

        if auth_line is not None:
            auth_dir = pathlib.Path(auth_line.split(" ", 1)[1])

            if not auth_dir.exists():
                raise FileNotFoundError("ClientOnionAuthDir is specified in torrc, but directory "
                                        f"doesn't exist! Path: '{auth_dir}'")
        else:
            auth_dir = self._add_torrc_auth_dir(torbrowser_torrc)

        self._log.debug(f"Found Tor Browser client authorization directory at '{auth_dir}'")
        return auth_dir

    def _add_torrc_auth_dir(self, torbrowser_torrc):
        """Creates an "onion-auth" directory in the same directory as the given torrc path and
        adds it as ClientOnionAuthDir to the given torrc file.

        Args:
            torbrowser_torrc: A pathlib object containing the path to the Tor configuration file.

        Returns:
            A pathlib object containing the path to the created client authorization directory.
        """

        # Take the parent folder of the torrc-path and add "onion-auth", which is usually the
        # default client onion auth directory
        auth_dir = torbrowser_torrc.parent / "onion-auth"
        auth_dir.mkdir(mode=0o700, exist_ok=True)

        with open(torbrowser_torrc, "a") as f:
            f.write(f"ClientOnionAuthDir {auth_dir}\n")

        self._log.debug(f"Added new Tor Browser client authorization directory '{auth_dir}'")

        return auth_dir

    def _get_registered_devices(self):
        """Reads all registered smart home devices from the JSON file and loads them in a
        dictionary. Validates all values of the dictionary. If one of them is invalid a TypeError
        is raised and the JSON file has to be inspected manually.

        Returns:
            A nested dictionary with the device name as key and the dictionary containing the Tor
            Onion address, port, https usage, public key and private key as value.

        Raises:
            TypeError: One of the values in the JSON file is invalid (detailed description given).
        """

        registered_devices = dict()

        if self._registered_devices_file.exists():
            registered_devices = json.loads(self._registered_devices_file.read_text())

            # Validate all devices loaded from the JSON file
            values = ["onion_address", "port", "https", "public_key", "private_key"]
            onion_addresses = list()
            for device_name, device_value in registered_devices.items():
                # Check if all required values are present for the current device
                if values != [*device_value]:
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' doesn't match the required structure!")

                # Validate every value
                if not validation.validate_onion_v3_address(device_value["onion_address"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid Tor Onion address!")
                if not validation.validate_port(device_value["port"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid port!")
                if type(device_value["https"]) is not bool:
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid HTTPS value!")
                if not validation.validate_base32_key(device_value["public_key"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid public key!")
                if not validation.validate_base32_key(device_value["private_key"]):
                    raise TypeError(
                        f"The device '{device_name}' in the JSON file "
                        f"'{self._registered_devices_file}' has an invalid private key!")

                # Check for Tor Onion address duplicates
                if device_value["onion_address"] in onion_addresses:
                    raise TypeError(f"The Tor Onion address '{device_value['onion_address']}' is "
                                    "registered for multiple devices!")
                else:
                    onion_addresses.append(device_value["onion_address"])

        return registered_devices

    def _add_registered_client_auths(self):
        """Adds the client authorization file for all registered clients."""

        for device_name, device_value in self._registered_devices.items():
            self._add_onion_service_auth(device_name, device_value["onion_address"],
                                         device_value["private_key"])
    
    def _delete_registered_clients_auths(self):
        """Deletes the client authorization file for all registered clients."""

        for device_name, device_value in self._registered_devices.items():
            try:
                tor.delete_onion_service_auth(
                    self._torbrowser_auth_dir, device_name, device_value["onion_address"],
                    device_value["private_key"])
            except Exception as error:
                self._log.error(f"Error while deleting the client authorization file for "
                                f"device '{device_name}': {error}")
