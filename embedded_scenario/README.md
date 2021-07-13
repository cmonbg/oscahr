# OSCAHR - Onion-Secured Smart Home Remote Access - Embedded Scenario
* Version: 0.5.9
* Date: 13.07.2021
* Author: Simon Birngruber ([IoT-Lab](https://github.com/IoT-Lab-FH-OOE), University of Applied Sciences Upper Austria, [Campus Hagenberg](https://www.fh-ooe.at/si/))
* License: MIT

## Description
For general information about the embedded scenario see the main README of OSCAHR.

## Requirements
### Smart Home Device
* Python in version 3.8.0 or greater
* Tor in version 0.3.5.7 or greater, install on debian with `apt install tor`
* Python-Packages listed in `requirements_smarthomedevice.txt`, install with `pip install -r requirements_smarthomedevice.txt`

### Client
* Python in version 3.8.0 or greater
* Tor in version 0.3.5.7 or greater, install on debian with `apt install tor`
* Python-Packages listed in `requirements_client.txt`, install with `pip install -r requirements_client.txt`


OSCAHR embedded scenario version 0.5.9 was tested on Ubuntu 20.04.2 LTS with following versions installed:
* cryptography 3.4.7
* packaging 20.9
* PySocks 1.7.1
* Python 3.9.5
* questionary 1.9.0
* stem 1.8.0
* Tor 0.4.5.9

## Usage
### Smart Home Device
```
usage: oscahr_smarthomedevice.py [-h] [-v | -s]

Start OSCAHR embedded scenario in smart home device mode.

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity to debug level
  -s, --silent   deactivate console log output
```

To start the smart home device in background you can use `nohup`: `nohup ./oscahr_smarthomedevice.py -s >/dev/null 2>&1 &`

### Client
```
usage: oscahr_client.py [-h] [-v]

Start OSCAHR embedded scenario in client mode.

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  increase output verbosity to debug level
```
