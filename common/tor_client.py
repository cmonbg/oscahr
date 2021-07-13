"""Collection of Tor client-side functions used by OSCAHR.

This module is part of the OSCAHR common package and contains a collection of Tor client-side
functions which multiple components of OSCAHR use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import base64
import json
import logging

# Third party imports
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          PublicFormat)

# Local application imports
import common.validation as validation

# Module constants
CLIENT_AUTH_EXTENSION = ".auth_private"

# Module variables
_log = logging.getLogger()  # get root logger


def generate_keypair():
    """Generates a private and public X25519 key and converts them to the format used by Tor.
    
    Returns:
        The formatted private and public key in a tuple.

    Raises:
        TypeError: The generated keys are invalid.
    """

    private_key_obj = X25519PrivateKey.generate()
    public_key_obj = private_key_obj.public_key()

    # Extract raw key bytes from objects
    private_key_bytes = private_key_obj.private_bytes(Encoding.Raw, PrivateFormat.Raw,
                                                      NoEncryption())
    public_key_bytes = public_key_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Encode to base32, decode from byte to string and remove "====" tail
    private_key = base64.b32encode(private_key_bytes).decode()[:-4]
    public_key = base64.b32encode(public_key_bytes).decode()[:-4]

    if not validation.validate_base32_key(private_key) or \
            not validation.validate_base32_key(public_key):
        raise TypeError("Keypair generation resulted in invalid keys!")
    else:
        return private_key, public_key


def add_onion_service_auth(auth_dir, device_name, onion_address, private_key):
    """Adds a client authorization file to the configured Tor Onion Service authorization
    directory and therefore activates client authorization for the given Onion address with
    the given private key.

    Args:
        auth_dir: A pathlib object containing the path to the Tor client authorization directory.
        device_name: Name of the smart home device as string.
        onion_address: Onion address of the Onion Service as string.
        private_key: Private key of the client as string.

    Raises:
        TypeError: The given Onion address or the given keypair is invalid.
        ValueError: The client authorization file to be created already exists and doesn't match
            the expected values.
    """

    if not validation.validate_onion_v3_address(onion_address):
        raise TypeError(f"Invalid Tor Onion address for device '{device_name}'!")
    elif not validation.validate_base32_key(private_key):
        raise TypeError(f"Invalid private key for device '{device_name}'!")
    else:
        private_client_file = auth_dir / (device_name + CLIENT_AUTH_EXTENSION)

        if private_client_file.exists():
            try:
                compare_onion_service_auth(private_client_file, onion_address, private_key)

                _log.debug(f"Using already existing authorization file '{private_client_file}'")
            except ValueError:
                raise ValueError(
                    f"File '{private_client_file}' already exists but contains other values than "
                    "expected. Please rename it or remove it manually if it isn't needed anymore "
                    "and try again!")
        else:
            # -6 -> cut .onion
            private_client_file.write_text(f"{onion_address[:-6]}:descriptor:x25519:{private_key}")
            private_client_file.chmod(0o600)

            _log.debug(f"Added onion service authorization file to '{private_client_file}'")


def delete_onion_service_auth(auth_dir, device_name, onion_address, private_key):
    """Deletes the private client authorization file of the given smart home device.
    If the client authorization file doesn't exist writes an error to log but doesn't raise
    an exception.
    
    Args:
        auth_dir: A pathlib object containing the path to the Tor client authorization directory.
        device_name: Name of the smart home device as string.
        onion_address: Onion address of the Onion Service as string.
        private_key: Private key of the client as string.
    """

    private_client_file = auth_dir / (device_name + CLIENT_AUTH_EXTENSION)

    if not private_client_file.exists():
        _log.error(f"Client authorization file '{private_client_file}' not found, aborted "
                   "removal!")
    else:
        compare_onion_service_auth(private_client_file, onion_address, private_key)

        private_client_file.unlink()
        _log.debug(f"Successfully removed client authorization file '{private_client_file}'")


def compare_onion_service_auth(auth_file, onion_address, private_key):
    """Compares the given Tor Onion address and the given private key to match to those in the
    given private client authorization file.

    Args:
        auth_file: A pathlib object containing the path to the Tor client authorization file.
        onion_address: Onion address of the Onion Service as string.
        private_key: Private key of the client as string.

    Raises:
        ValueError: The client authorization file has a wrong structure or the given values don't
            match.
    """

    file_content = auth_file.read_text().strip()

    try:
        file_onion_address, _, _, file_private_key = file_content.split(":")
    except ValueError:
        raise ValueError(f"Client authorization file '{auth_file}' doesn't match the required "
                         "structure, please inspect manually!")

    if (file_onion_address + ".onion") != onion_address or file_private_key != private_key:
        raise ValueError(f"Client authorization file '{auth_file}' contains other values than "
                         "expected, please inspect manually!")


def set_registered_devices(registered_devices, registered_devices_file):
    """Saves the given registered devices dictionary as JSON to the given filepath.
    
    Args:
        registered_devices: A dictionary containing the registered devices.
        registered_devices_file: A pathlib object containing the path to the JSON file.
    """

    registered_devices_file.write_text(json.dumps(registered_devices))
