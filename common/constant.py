"""Collection of constants used by OSCAHR.

This module is part of the OSCAHR common package and contains a collection of constants which
multiple components of the OSCAHR embedded scenario use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

COM_PORT = 42021  # Static OSCAHR communication port
ROUTER_PORT = 80
ERROR_RESPONSE = "ERROR"
SUCCESS_RESPONSE = "SUCCESS"
DELIMITER_PARAM = ":"
DELIMITER_END = ";"
LOCAL_COMMANDS = [
    "unused",
    "unused2",
    "activate_remote_access",
    "deactivate_remote_access",
    "delete_onion_service",
    "exit",
]
LOCAL_COMMANDS_TEXT = [
    "Unused command slot",
    "Unused command slot 2",
    "Activate remote access",
    "Deactivate remote access",
    "Delete Tor Onion Service",
    "Disconnect and back to device menu"
]
REMOTE_COMMANDS = [
    LOCAL_COMMANDS[0],  # Unused command slot
    LOCAL_COMMANDS[1],  # Unused command slot 2
    LOCAL_COMMANDS[5]   # Exit
]
REMOTE_COMMANDS_TEXT = [
    LOCAL_COMMANDS_TEXT[0],  # Unused command slot
    LOCAL_COMMANDS_TEXT[1],  # Unused command slot 2
    LOCAL_COMMANDS_TEXT[5]   # Exit
]
