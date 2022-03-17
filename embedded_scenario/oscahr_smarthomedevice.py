#!/usr/bin/env python3

"""Smart Home device main of the OSCAHR embedded scenario.

This module is the main wrapper to start the OSCAHR embedded scenario Smart Home device (server). 

Version: 0.5.9
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import argparse
import logging
import sys
import traceback

# Local application imports
from common.config import OscahrConfig
from smarthomedevice import SmartHomeDevice

# Module variables
_log = logging.getLogger()  # get root logger


def main():
    """Main function to start the OSCAHR smart home device of the embedded scenario."""

    parser = argparse.ArgumentParser(description="Start OSCAHR embedded scenario in smart home "
                                                 "device mode.")
    logging_group = parser.add_mutually_exclusive_group()
    logging_group.add_argument("-v", "--verbose", action="store_true",
                               help="increase output verbosity to debug level")
    logging_group.add_argument("-s", "--silent", action="store_true",
                               help="deactivate console log output")
    args = parser.parse_args()

    try:
        oscahr_config = OscahrConfig(verbose=args.verbose, silent=args.silent)

        with SmartHomeDevice(oscahr_config) as shd:
            shd.start_server()

    except KeyboardInterrupt:
        _log.debug("Interrupted by user!")
    except Exception as error:
        _log.error(f"A {type(error).__name__} occured: {error} in {traceback.print_exc()}")
    finally:
        oscahr_config.cleanup()
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
