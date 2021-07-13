"""Collection of validation functions used by OSCAHR.

This module is part of the OSCAHR common package and contains a collection of validation functions
which multiple components of OSCAHR use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import base64
import hashlib
import ipaddress
import re


def validate_device_name(device_name):
    """Validates a given device name. Allowed characters are A-Z, a-z, _, - and 0-9. Minimum is
    one character, maximum are 64 characters. Removes all leading and trailing spaces before
    validation.

    Args:
        device_name: Device name to validate as string.

    Returns:
        True if the given string is an allowed device name, False if not.
    """

    if device_name is not None:
        search = re.compile(r'^[a-zA-Z_\-\d]{1,64}$').search
        return bool(search(device_name.strip()))
    return False


def validate_device_name_text(device_name):
    """Extends the validate_device_name function with a return text if the validation fails.
    Can be used with the validate option of the questionary package.

    Args:
        device_name: Device name to validate as string.

    Returns:
        True if the given string is an allowed device name, an error message if not.
    """

    if validate_device_name(device_name):
        return True
    else:
        return "Only alphabetic and numeric characters, - and _ are allowed and the maximum is " \
               "64 characters!"


def validate_ip_address(ip_address):
    """Validates a given IP address.

    Args:
        ip_address: IP address to validate as string.

    Returns:
        True if the given string is a valid IPv4 or IPv6 address, False if not.
    """

    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def validate_ip_address_text(ip_address):
    """Extends the validate_ip_address function with a return text if the validation fails.
    Can be used with the validate option of the questionary package.

    Args:
        ip_address: IP address to validate as string.

    Returns:
        True if the given string is a valid IPv4 or IPv6 address, an error message if not.
    """

    if validate_ip_address(ip_address):
        return True
    else:
        return "Please enter a valid IPv4 or IPv6 address!"


def validate_port(port):
    """Validates a given port number.

    Args:
        port: Integer port number to validate.

    Returns:
        True if the given value is a valid port between 0 and 65536, False if not.
    """

    try:
        return True if 1 <= int(port) <= 65535 else False
    except (ValueError, TypeError):
        return False


def validate_port_text(port):
    """Extends the validate_port function with a return text if the validation fails.
    Can be used with the validate option of the questionary package.

    Args:
        port: Integer port number to validate.

    Returns:
        True if the given string is a valid port between 0 and 65536, an error message if not.
    """

    if validate_port(port):
        return True
    else:
        return "Please enter a valid port between 0 and 65536!"


def validate_onion_v3_address(onion_address):
    """Validates a given Onion v3 address (whole domain including the ".onion" TLD) based on the
    Tor Rendezvous Specification Version 3
    (https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2135).

    Args:
        onion_address: Tor Onion address to validate as string.

    Returns:
        True if the given string is a valid Onion v3 address, False if not.
    """

    if onion_address is not None:
        search = re.compile(r'^[a-z2-7]{56}.onion$').search
        if bool(search(onion_address)):
            # onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
            b32_decoded = base64.b32decode(onion_address.upper()[:-6])  # -6 -> cut .onion
            pubkey, checksum, version = b32_decoded[:32], b32_decoded[32:34], b32_decoded[34:]

            # VERSION is an one byte version field (default value '\x03')
            if version != b"\x03":
                return False

            # CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
            target_checksum = \
                hashlib.sha3_256(b".onion checksum" + pubkey + version).digest()[:2]

            if checksum == target_checksum:
                return True
    return False


def validate_onion_v3_address_text(onion_address):
    """Extends the validate_onion_v3_address function with a return text if the validation fails.
    Can be used with the validate option of the questionary package.

    Args:
        onion_address: Tor Onion address to validate as string.

    Returns:
        True if the given string is a valid Onion v3 address, an error message if not.
    """

    if validate_onion_v3_address(onion_address):
        return True
    else:
        return "Please enter a valid Tor Onion v3 address!"


def validate_base32_key(key):
    """Validates a given base32 key.

    Args:
        key: Base32 key to validate as string.

    Returns:
        True if the given string is a valid base32 key, False if not.
    """

    if key is not None:
        search = re.compile(r'^[A-Z2-7]{52}$').search
        return bool(search(key))
    return False


def validate_base32_key_text(key):
    """Extends the validate_base32_key function with a return text if the validation fails.
    Can be used with the validate option of the questionary package.

    Args:
        key: Base32 key to validate as string.

    Returns:
        True if the given string is a valid base32 key, an error message if not.
    """

    if validate_base32_key(key):
        return True
    else:
        return "Please enter a valid key!"


def validate_print_ip_address(ip_address):
    """Validates the given IP address and returns a printable version. For IPv4 addresses no
    changes are made, for IPv6 addresses brakets are added.

    Args:
        ip_address: IP address to validate as string.
    
    Returns:
        A printable version of the given IP address as string.

    Raises:
        ValueError: The given IP address is invalid.
    """

    if type(ipaddress.ip_address(ip_address)) is ipaddress.IPv6Address:
        return "[" + ip_address + "]"
    elif type(ipaddress.ip_address(ip_address)) is ipaddress.IPv4Address:
        return ip_address
    else:
        raise ValueError("Invalid IP address!")
