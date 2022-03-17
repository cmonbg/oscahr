"""Universal config module for OSCAHR.

This module is part of the OSCAHR common package and contains a collection of config methods which
multiple components of OSCAHR use.

Version: 0.6.1
Date: 13.07.2021
Author: Simon Birngruber (IoT-Lab, University of Applied Sciences Upper Austria, Campus Hagenberg)
License: MIT
"""

# Standard library imports
import logging
import os
import pathlib
import random
import shutil
import signal
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler

# Local application imports
import common.version as version


class OscahrConfig:
    """Class to configure an OSCAHR session.

    Allows to prepare the current OSCAHR scenario and offers several methods which are used by
    both OSCAHR scenarios.

    Attributes:
        oscahr_config_dir: Pathlib object containing the path to the OSCAHR config directory.
        tor_data_dir: Pathlib object containing the path to the OSCAHR tor directory.
        tor_proc: Popen object for the tor subprocess.
        tor_control_port: An integer representing the chosen control port for tor.
        tor_socks_port: An integer representing the chosen SOCKS5 port for tor.    
    """

    # Class constants
    _START_TOR_RETRIES = 3

    def __init__(self, oscahr_type, verbose=False, client=False, silent=False):
        """Initializes the Common object with mandatory variables.

        Args:
            verbose: Optional; A boolean indicating the console logger verbose level. Default is
                False.
            client: Optional; A boolean indicating if the calling device is a client. Default is
                False.
            silent: Optional; A boolean indicating if the console logger is deactivated. Default is
                False.
        """

        # Register the termination signal to be caught by the signal handler
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.oscahr_config_dir = self._create_oscahr_config_dir(oscahr_type)
        self._log = self._init_logger(verbose, client, silent)

        self._log.debug("Initializing Common object...")
        self._log.debug(f"OSCAHR config directory: {self.oscahr_config_dir}")

        self.tor_data_dir = self.oscahr_config_dir / "tor"
        self._pid_file = self.oscahr_config_dir / "oscahr.pid"
        self._tor_cookie_auth_file = self.tor_data_dir / "auth_cookie"

        self._pid_existed = None
        self._tor_path = None
        self.tor_proc = None
        self.tor_control_port = None
        self.tor_socks_port = None

    def prepare_oscahr_embedded(self, client=False):
        """Preparations to guarantee a successful start of OSCAHR embedded scenario (writes PID,
        checks Tor binary and does several version checks).
        
        Args:
            client: Optional; A boolean indicating if the calling device is a client. Default is
                False.
        """

        self._log.debug("New OSCAHR session started (embedded scenario)")
        self._write_pid()
        self._get_tor_path()
        version.check_python_version()
        version.check_package_versions(client)
        version.check_tor_version()

    def prepare_oscahr_proxy(self, client=False):
        """Preparations to guarantee a successful start of OSCAHR proxy scenario (writes PID and
        does several version checks). If client is True the Tor binary isn't needed, therefore the
        binary search and Tor version check is skipped.
        
        Args:
            client: Optional; A boolean indicating if the calling device is a client. Default is
                False.
        """

        self._log.debug("New OSCAHR session started (proxy scenario)")
        self._write_pid()
        version.check_python_version()
        version.check_package_versions(client, embedded=False)

        if not client:
            self._get_tor_path()
            version.check_tor_version()

    def start_tor(self, client_onion_auth_dir=None):
        """Starts a Tor subprocess and saves proccess handle to the object variable tor_proc.
        Configures Tor for client usage if a client authorization directory is given, otherwise
        configures Tor for running an Onion Service.
        Chooses a random control and socks port for every retry to prevent choosing an already
        used port.

        Args:
            client_onion_auth_dir: Optional; A pathlib object containing the path to the Tor Onion
                Service client authorization directory.

        Raises:
            RuntimeError: An error while starting the Tor subprocess occured more often than
                allowed by the class constant.
        """

        # Create subdirectory in OSCAHR config-dir
        self.tor_data_dir.mkdir(mode=0o700, exist_ok=True)

        for retry in range(self._START_TOR_RETRIES + 1):
            self.tor_control_port = random.randrange(50000, 55000)
            self._log.debug(f"Port {self.tor_control_port} was chosen as control port for the Tor "
                            "subprocess")

            # SOCKS5 proxy only needed for client
            if client_onion_auth_dir is not None:
                self.tor_socks_port = random.randrange(55000, 60000)
                self._log.debug(f"Port {self.tor_socks_port} was chosen as SOCKS5 port for the Tor"
                                " subprocess")

            tor_config = self._create_tor_config(client_onion_auth_dir)

            self.tor_proc = subprocess.Popen(
                [self._tor_path, "-f", tor_config],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            time.sleep(3)  # Wait for the Tor subprocess to start
            self.tor_proc.poll()  # Get returncode in the case the Tor subprocess terminated

            # Tor subprocess started successfully
            if self.tor_proc.returncode is None:
                break
            # Tor subprocess terminated but maximum retries are not reached
            elif retry < self._START_TOR_RETRIES:
                self._log.warning("Tor subprocess terminated with returncode "
                                  f"{self.tor_proc.returncode}. Retrying... "
                                  f"({retry + 1}/{self._START_TOR_RETRIES})")
                self.tor_proc = None
            # Tor subprocess terminated and maximum retries are reached
            else:
                self.tor_proc = None
                raise RuntimeError(f"Tor subprocess failed to start {self._START_TOR_RETRIES + 1} "
                                   "times!")

        self._log.debug("Successfully created Tor subprocess")

    def terminate_tor(self):
        """Terminates the Tor subprocess if one was started before."""

        if self.tor_proc is not None:
            self.tor_proc.terminate()
            self.tor_proc = None
            self._log.debug("Terminated Tor subprocess")

    def signal_handler(self, signum, frame):
        """Raises a RuntimeError with the signal number which caused the call to start error
        handling.
        """

        raise RuntimeError(f"Interrupted by signal number {signum}!")

    def cleanup(self):
        """Terminates the Tor subprocess, removes the PID file and writes a dividing line to log.
        """

        self._log.debug("Cleaning up config...")

        self.terminate_tor()

        if not self._pid_existed:
            try:
                self._pid_file.unlink()
                self._log.debug("Successfully removed PID file")
            except Exception as error:
                self._log.error(f"Couldn't remove PID file, {type(error).__name__}: {error}")

        self._log.debug("*" * 60)  # Add dividing line to log

    def _create_oscahr_config_dir(self, oscahr_type):
        """Creates config-dir in USERHOME/.config/oscahr if it doesn't exists.

        Returns:
            A pathlib object containing the path to the OSCAHR config directory.
        """

        oscahr_config_dir = pathlib.Path.home() / ".config" / "oscahr" / oscahr_type
        oscahr_config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        return oscahr_config_dir

    def _init_logger(self, verbose, client, silent):
        """Initializes the logger to log to the console and to the file "oscahr.log" in the
        OSCAHR config directory. Rotates the log every 10 MB and backups the last 5 log files.
        Format example: 2021-01-05 14:25:09,214 [INFO] New session started!

        Args:
            verbose: If True the log level of the console logger is set to DEBUG otherwise to INFO.
            client: If True and verbose is False only show the log message without date and log
                level at the console.
            silent: If True the console logger gets fully deactivated (logging only to file). This
                argument overwrites client and verbose arguments.
        
        Returns:
            The logger object.
        """

        log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

        # Initialize file logger
        log_file = self.oscahr_config_dir / "oscahr.log"
        # Rotate logs when they reach 10 MB and backup the last 5 log files
        log_file_handler = RotatingFileHandler(log_file, maxBytes=10000000, backupCount=5)
        log_file_handler.setFormatter(log_formatter)
        log_file_handler.setLevel(logging.DEBUG)

        if not silent:
            # Initialize console logger
            log_console_handler = logging.StreamHandler(sys.stdout)

            # If it's a client not in verbose mode only show the message without date and log level
            if client and not verbose:
                log_console_handler.setFormatter(logging.Formatter("%(message)s"))
            else:
                log_console_handler.setFormatter(log_formatter)

            # If verbose mode is on show everything, otherwise show only log level INFO and above
            if verbose:
                log_console_handler.setLevel(logging.DEBUG)
            else:
                log_console_handler.setLevel(logging.INFO)

        # Initialize root logger
        oscahr_logger = logging.getLogger()
        oscahr_logger.setLevel(logging.DEBUG)
        oscahr_logger.addHandler(log_file_handler)
        if not silent:
            oscahr_logger.addHandler(log_console_handler)

        # Set the logging level of the stem and asyncio library to warning to reduce console output
        logging.getLogger("stem").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)

        return oscahr_logger

    def _write_pid(self):
        """First checks if there is an existing process ID file in the OSCAHR config directory.
        If no existing PID was found gets the process ID of the current process and writes it to a
        PID file in the OSCAHR config directory.

        Raises:
            RuntimeError: An existing PID file was found.
        """

        if self._pid_file.exists():
            self._pid_existed = True
            print("PID file found, check if OSCAHR is not already running!")
            # if OSCAHR is not terminated with its exit method, the PID file will not be automatically deleted and
            # OSCAHR will fail to start again until the PID file is deleted somehow
            # raise RuntimeError(
            #     f"OSCAHR is already running with process ID {self._pid_file.read_text().strip()}!")
        else:
            self._pid_existed = False
            self._pid_file.write_text(str(os.getpid()))
            self._pid_file.chmod(0o600)

    def _get_tor_path(self):
        """Saves the path of the Tor binary to the object variable tor_path if one was found.

        Raises:
            FileNotFoundError: No Tor binary was found.
        """

        self._tor_path = shutil.which("tor")

        if self._tor_path is not None:
            logging.debug(f"Found Tor binary at '{self._tor_path}'")
        else:
            raise FileNotFoundError("No Tor binary found! Please install Tor or if already "
                                    "installed add the binary to your environment variables.")

    def _create_tor_config(self, client_onion_auth_dir=None):
        """Writes a Tor config-file (torrc) to the Tor data directory. Configures Tor for client
        usage if a client authorization directory is given, otherwise configures Tor for running
        an Onion Service.

        Args:
            client_onion_auth_dir: Optional; A pathlib object containing the path to the Tor Onion
                Service client authorization directory.

        Returns:
            A pathlib object containing the path to the Tor config file.
        """

        torrc_file = self.tor_data_dir / "torrc"

        torrc = (f"DataDirectory {self.tor_data_dir}\n"
                 f"ControlPort 127.0.0.1:{self.tor_control_port}\n"
                 "CookieAuthentication 1\n"
                 f"CookieAuthFile {self._tor_cookie_auth_file}\n")

        if client_onion_auth_dir is None:  # Server
            torrc += "SOCKSPort 0\n"  # Deactivate SOCKS5 proxy
        else:  # Client
            torrc += (f"ClientOnionAuthDir {client_onion_auth_dir}\n"
                      # Configure SOCKS5 proxy to be bound to localhost IPv4 address 127.0.0.1.
                      # Furthermore only accept connections from localhost IPv4 address 127.0.0.1
                      # and reject all others.
                      f"SOCKSPort 127.0.0.1:{self.tor_socks_port}\n"
                      "SOCKSPolicy accept 127.0.0.1\n"
                      "SOCKSPolicy reject *\n")

        torrc_file.write_text(torrc)
        torrc_file.chmod(0o600)
        self._log.debug(f"Tor config written to '{torrc_file}'")

        return torrc_file
