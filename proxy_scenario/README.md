# OSCAHR - Onion-Secured Smart Home Remote Access - Proxy Scenario
* Version: 0.3.2
* Date: 13.07.2021
* Author: Simon Birngruber ([IoT-Lab](https://github.com/IoT-Lab-FH-OOE), University of Applied Sciences Upper Austria, [Campus Hagenberg](https://www.fh-ooe.at/si/))
* License: MIT

## Description
For general information about the proxy scenario see the main README of OSCAHR.

## Requirements
### Proxy
* Python in version 3.8.0 or greater
* Tor in version 0.3.5.7 or greater, install on debian with `apt install tor`
* Python-Packages listed in `requirements_proxy.txt`, install with `pip install -r requirements_proxy.txt`

### Client
* Python in version 3.8.0 or greater
* Tor Browser, install on Debian with `apt install torbrowser-launcher` or via manual download from https://www.torproject.org/
* Python-Packages listed in `requirements_client.txt`, install with `pip install -r requirements_client.txt`

OSCAHR proxy scenario version 0.3.2 was tested on Ubuntu 20.04.2 LTS with following versions installed:
* cryptography 3.4.7
* packaging 20.9
* Python 3.9.5
* questionary 1.9.0
* stem 1.8.0
* Tor 0.4.5.9
* Tor Browser 10.0.18

## Usage
### Proxy
```
usage: oscahr_proxy.py [-h] [-m] [-v | -s]

Start OSCAHR proxy scenario in proxy mode.

optional arguments:
  -h, --help     show this help message and exit
  -m, --manage   manage smart home devices (add/delete/modify)
  -v, --verbose  increase output verbosity to debug level
  -s, --silent   deactivate console log output
```

To start the proxy in background you can use `nohup`: `nohup ./oscahr_proxy.py -s >/dev/null 2>&1 &`

### Client
```
usage: oscahr_client.py [-h] [-v]

Start OSCAHR proxy scenario in client mode.

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity to debug level
```
