"""Collection of Tor server-side functions used by OSCAHR.

This module is part of the OSCAHR common package and contains a collection of Tor server-side
functions which multiple components of OSCAHR use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import logging
import os
import shutil
import time

# Third party imports
from stem import Signal
from stem.control import Controller

# Local application imports
import common.validation as validation

# Module constants
AUTH_CLIENT_FOLDER = "authorized_clients"
CLIENT_AUTH_EXTENSION = ".auth"

# Module variables
_log = logging.getLogger()  # get root logger


def create_disk_v3_onion_service(onion_service_dir, tor_control_port, client_pub_key,
                                 port, ip_address="127.0.0.1", client_name=None):
    """Creates a permanent Tor v3 Onion Service.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        tor_control_port: An integer Tor control port number.
        client_pub_key: A public key of the client to add as string, to enforce client
            authorization.
        port: An integer port number of the service to create an Onion Service for.
        ip_address: Optional; An IP address as string of the service to create an Onion Service
            for. Default is localhost (127.0.0.1).
        client_name: Optional; The name of the client to add as string.

    Returns:
        The Onion address of the created Tor Onion Service as string.

    Raises: 
        FileExistsError: The given Onion Service directory already exists.
    """

    try:
        onion_service_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError:
        raise FileExistsError(f"The directory '{onion_service_dir}' already exists, please remove "
                              "it manually if it isn't needed anymore and try again!")

    add_disk_v3_onion_service_auth(onion_service_dir, client_pub_key, client_name)

    return start_disk_v3_onion_service(onion_service_dir, tor_control_port, port, ip_address,
                                       new=True)


def remove_disk_v3_onion_service(onion_service_dir, tor_control_port):
    """Removes the given Onion Service including all client authorization files.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        tor_control_port: An integer Tor control port number.

    Raises:
        RuntimeError: No Tor Onion Service exists at the given directory.
        FileExistsError: The Onion Service directory wasn't removed properly.
    """

    if not check_existing_onion_service(onion_service_dir):
        raise RuntimeError("No existing Tor Onion Service, aborted removal!")
    else:
        shutil.rmtree(onion_service_dir)
        _log.debug(f"Successfully removed Tor Onion Service directory {onion_service_dir}")

        if onion_service_dir.exists():
            raise FileExistsError("Tor Onion Service directory still exists after removal!")
        else:
            # Fix stem/tor bug when dealing with windows paths
            if os.name == 'nt':
                onion_service_dir = str(onion_service_dir).replace("\\", "/")

            with Controller.from_port(port=tor_control_port) as controller:
                controller.authenticate()  # Uses authentication cookie from path given in torrc
                _log.debug("Authenticated to the Tor controller")

                controller.remove_hidden_service(str(onion_service_dir))
                _log.info("Successfully removed Tor Onion Service")


def start_disk_v3_onion_service(onion_service_dir, tor_control_port, port, ip_address="127.0.0.1",
                                new=False):
    """Starts an existing Tor v3 Onion Service or creates a new one if "new" is True.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        tor_control_port: An integer Tor control port number.
        port: An integer port number of the service to create an Onion Service for.
        ip_address: Optional; An IP address as string of the service to create an Onion Service
            for. Default is localhost (127.0.0.1). 
        new: Optional; A boolean indicating to create an new Tor Onion Service. Default is False.

    Returns:
        The Onion address of the Onion Service.

    Raises:
        RuntimeError: No eixsting Onion Service was found and "new" is False.
        RuntimeError: The Onion address isn't set after starting the Onion Service.
    """

    onion_service_address = None

    if check_existing_onion_service(onion_service_dir) or new:
        if check_existing_onion_service_auth(onion_service_dir):
            check_maximum_clients(onion_service_dir, start=True)

            # Fix stem/tor bug when dealing with windows paths
            if os.name == 'nt':
                onion_service_dir = str(onion_service_dir).replace("\\", "/")

            # If a IPv6 address is given add brackets, otherwise the Onion Service isn't working
            # torrc also needs brackets: https://gitlab.torproject.org/legacy/trac/-/issues/6551
            ip_address = validation.validate_print_ip_address(ip_address)

            with Controller.from_port(port=tor_control_port) as controller:
                controller.authenticate()  # Uses authentication cookie from path given in torrc
                _log.debug("Authenticated to the Tor controller")

                _log.debug(f"Creating the Tor Onion Service in {onion_service_dir}")
                onion_service = controller.create_hidden_service(
                    path=str(onion_service_dir), port=port, target_address=ip_address)
                onion_service_address = onion_service.hostname
                _log.info(f"Successfully started Tor Onion Service at {onion_service_address}")
        else:
            _log.warning(f"Existing Tor Onion Service found in '{onion_service_dir}', but a client"
                         " authorization file is missing. Not starting, please inspect manually!")
    else:
        raise RuntimeError("No existing Tor Onion Service found!")

    if onion_service_address is None:
        raise RuntimeError("Error while starting the Tor Onion Service!")
    else:
        return onion_service_address


def reload_disk_v3_onion_service(onion_service_dir, tor_control_port, port,
                                 ip_address="127.0.0.1"):
    """Reloads the Tor controller and readds the given Tor Onion Service to the new Tor controller.
    
    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        tor_control_port: An integer Tor control port number.
        port: An integer port number of the service to readd an Onion Service for.
        ip_address: Optional; An IP address as string of the service to readd an Onion Service
            for. Default is localhost (127.0.0.1).
    
    Raises:
        RuntimeError: There is no existing Tor Onion Service at the given directory.
    """

    if not check_existing_onion_service(onion_service_dir):
        raise RuntimeError("No existing Tor Onion Service, aborted reload!")
    else:
        # Fix stem/tor bug when dealing with windows paths
        if os.name == 'nt':
            onion_service_dir = str(onion_service_dir).replace("\\", "/")

        # If a IPv6 address is given add brackets, otherwise the Onion Service isn't working
        # torrc also needs brackets: https://gitlab.torproject.org/legacy/trac/-/issues/6551
        ip_address = validation.validate_print_ip_address(ip_address)

        with Controller.from_port(port=tor_control_port) as controller:
            controller.authenticate()  # Uses authentication cookie from path given in torrc
            _log.debug("Authenticated to the Tor controller")

            controller.signal(Signal.HUP)
            _log.debug("Reloaded Tor")

            controller.create_hidden_service(path=str(onion_service_dir), port=port,
                                             target_address=ip_address)
            _log.debug("Readded the Tor Onion Service")


def add_disk_v3_onion_service_auth(onion_service_dir, client_pub_key, client_name=None):
    """Adds a new client authorization file including the given client public key to the given Tor
    Onion Service.
    The filename of the client authorization file is the client name if given, otherwiese
    the current Unix timestamp.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        client_pub_key: Public key of the client to add as string.
        client_name: Optional; Name of the client to add as string. 

    Raises:
        TypeError: The given client public key is invalid.
    """

    if not validation.validate_base32_key(client_pub_key):
        raise TypeError("Invalid public key!")
    else:
        check_maximum_clients(onion_service_dir)

        auth_dir = onion_service_dir / AUTH_CLIENT_FOLDER
        auth_dir.mkdir(mode=0o700, exist_ok=True)

        if client_name is None:
            client_file = auth_dir / (str(time.time()).replace(".", "") + CLIENT_AUTH_EXTENSION)
        else:
            client_file = auth_dir / (client_name + CLIENT_AUTH_EXTENSION)

        client_file.write_text(f"descriptor:x25519:{client_pub_key}")
        client_file.chmod(0o600)

        _log.debug(f"Added new client public key to {client_file}")


def remove_disk_v3_onion_service_auth(onion_service_dir, client_pub_key, tor_control_port,
                                      port, ip_address="127.0.0.1"):
    """Removes the Tor Onion Service client authorization file of the client with the given
    public key. If that was the last registered client, the whole Onion Service is removed.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        client_pub_key: Public key of the client to remove as string.
        tor_control_port: An integer Tor control port number.
        port: An integer port number of the service to readd an Onion Service for.
        ip_address: Optional; An IP address as string of the service to readd an Onion Service
            for. Default is localhost (127.0.0.1).

    Raises:
        TypeError: The given client public key is invalid.
        RuntimeError: There is no registered client with the given public key.
        FileExistsError: The Onion Service authorization file wasn't removed properly.
    """

    if not validation.validate_base32_key(client_pub_key):
        raise TypeError("Invalid public key!")
    else:
        client_auth_filepath = check_existing_onion_service_auth(onion_service_dir, client_pub_key)
        if client_auth_filepath is False:
            raise RuntimeError(f"No client with public key '{client_pub_key}' is registered!")
        else:
            client_auth_filepath.unlink()
            _log.info("Successfully removed client authorization file")

            if not client_auth_filepath.exists():
                # Check if there is another client authorization file otherwise remove whole
                # Onion Service to avoid access without client authorization
                if check_existing_onion_service_auth(onion_service_dir):
                    reload_disk_v3_onion_service(onion_service_dir, tor_control_port, port,
                                                 ip_address)
                else:
                    remove_disk_v3_onion_service(onion_service_dir, tor_control_port)
            else:
                raise FileExistsError("Client public key file still exists after removal!")


def check_existing_onion_service(onion_service_dir):
    """Checks for an existing Tor Onion Service in the given directory.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
    
    Returns:
        True if a Tor Onion Service exists in the given directory, False if not.
    """

    hostname_file = onion_service_dir / "hostname"

    if hostname_file.exists():
        if validation.validate_onion_v3_address(hostname_file.read_text().strip()):
            return True

    return False


def check_existing_onion_service_auth(onion_service_dir, public_key=None):
    """Checks if there is at least one registered client in the given Tor Onion Service directory
    (also checks if the content of the client authorization file is valid).
    If a public key is given checks if there is a registered client with the given public key.
    
    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        public_key: Public key of the client to search as string.

    Returns:
        - True if no public key is given and if there is at least one registered client
          in the given Tor Onion Service directory, False if not.
        - The filepath to the client authorization file if a public key is given, False if no
          client with the given public key was found.
    """

    auth_dir = onion_service_dir / AUTH_CLIENT_FOLDER

    if auth_dir.exists():
        auth_files = list(auth_dir.glob("*" + CLIENT_AUTH_EXTENSION))
        for auth_file in auth_files:
            auth_content = auth_file.read_text().strip().split(":")
            if len(auth_content) == 3 and auth_content[0] == "descriptor" and \
                    auth_content[1] == "x25519":
                if public_key is None and validation.validate_base32_key(auth_content[2]):
                    return True
                elif public_key == auth_content[2]:
                    return auth_dir / auth_file

    return False


def check_maximum_clients(onion_service_dir, start=False):
    """Gets the current number of clients (.auth files in the given Tor Onion Service directory)
    and checks if this number is below the maximum clients allowed.
    An official maximum number for clients per Onion Service from Tor wasn't found. Manual
    tests showed that starting with 369 client authorization files the Onion Service isn't
    reachable anymore. Therefore a maximum of 360 clients was chosen.

    Args:
        onion_service_dir: A pathlib object containing the path to the Tor Onion Service directory.
        start: Optional; A boolean indicating if the function is called at the start (no new client
            is added afterwards). Default is False.

    Raises:
        IndexError: The number of clients is above the maximum clients allowed.
    """

    MAXIMUM = 360

    auth_dir = onion_service_dir / AUTH_CLIENT_FOLDER

    if auth_dir.exists():
        count = len(list(auth_dir.glob("*" + CLIENT_AUTH_EXTENSION)))

        # If the call happened not at the start, add one, because a client authorization file
        # will be added afterwards
        if not start:
            count += 1

        if count > MAXIMUM:
            raise IndexError("Exceeded the maximum number of allowed clients!")
