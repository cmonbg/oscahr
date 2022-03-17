"""Collection of version-check functions used by OSCAHR.

This module is part of the OSCAHR common package and contains a collection of version-check
functions which multiple components of OSCAHR use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
from importlib.metadata import version as package_version
import sys

# Third party imports
# stem.version import in function check_tor_version() to avoid error for missing package
from packaging.version import parse as parse_version


def check_python_version():
    """Checks whether Python is installed at least in the version required by OSCAHR (3.8).
    
    Raises:
        RuntimeError: The installed Python version is too old.
    """

    PYTHON_MIN = (3, 8, 0)

    if sys.version_info < PYTHON_MIN:
        raise RuntimeError(f"Python is installed in version {sys.version_info.major}."
                           f"{sys.version_info.minor}.{sys.version_info.micro}, OSCAHR requires at"
                           f" least version {PYTHON_MIN[0]}.{PYTHON_MIN[1]}.{PYTHON_MIN[2]}!")


def check_package_versions(client=False, embedded=True):
    """Checks whether the required Python packages are installed at least in the version
    required by OSCAHR. The version numbers are also listed in the corresponding requirements file.
    Different version checks for clients and the two scenarios embedded (default) and
    proxy (used when embedded is False).

    Args:
        client: Optional; A boolean indicating to check for client packages. Default is False.
        embedded: Optional; A boolean indicating to check for packages needed in the embedded
            scneario. Default is True.

    Raises:
        RuntimeError: A package version is too old.
    """

    versions = {
        "packaging": {
            "minimum": parse_version("20.0"),
            "current": parse_version(package_version("packaging"))
        }
    }

    if embedded:
        # Embedded scenario - general
        versions.update({
            "stem": {
                "minimum": parse_version("1.8.0"),
                "current": parse_version(package_version("stem"))
            }
        })

        # Embedded scenario - client specific
        if client:
            versions.update({
                "cryptography": {
                    "minimum": parse_version("3.3"),
                    "current": parse_version(package_version("cryptography"))
                },
                "PySocks": {
                    "minimum": parse_version("1.7.1"),
                    "current": parse_version(package_version("PySocks"))
                },
                "questionary": {
                    "minimum": parse_version("1.9.0"),
                    "current": parse_version(package_version("questionary"))
                }
            })

    else:
        # Proxy scenario - general
        versions.update({
            "questionary": {
                "minimum": parse_version("1.9.0"),
                "current": parse_version(package_version("questionary"))
            }
        })

        if client:
            # Proxy scenario - client specific
            versions.update({
                "cryptography": {
                    "minimum": parse_version("3.3"),
                    "current": parse_version(package_version("cryptography"))
                },
                "psutil": {
                    "minimum": parse_version("5.8.0"),
                    "current": parse_version(package_version("psutil"))
                }
            })
        else:
            # Proxy scenario - proxy specific
            versions.update({
                "stem": {
                    "minimum": parse_version("1.8.0"),
                    "current": parse_version(package_version("stem"))
                }
            })

    for package in versions:
        if versions[package]["current"] < versions[package]["minimum"]:
            raise RuntimeError(
                f"Package '{package}' is installed in version {versions[package]['current']}, "
                f"OSCAHR requires at least version {versions[package]['minimum']}!")


def check_tor_version():
    """Checks whether Tor is installed at least in the version required by OSCAHR.
    Version 0.3.5.7 is the first one which creates Tor v3 Onion Services per default, therefore
    that's the minium version.

    Raises:
        RuntimeError: The installed Tor version is too old.
    """

    # don't check version for now, since 'tor --version' does not produce any output on the router
    return

    import stem.version as stem_version

    TOR_MIN = "0.3.5.7"
    tor_cur = stem_version.get_system_tor_version()

    if tor_cur < stem_version.Version(TOR_MIN):
        raise RuntimeError(f"Installed Tor version {tor_cur} is NOT compatible with OSCAHR "
                           f"(requires version {TOR_MIN} and upwards)!")
