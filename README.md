# OSCAHR - Onion-Secured Smart Home Remote Access
* Date: 13.07.2021
* Author: Simon Birngruber ([IoT-Lab](https://github.com/IoT-Lab-FH-OOE), University of Applied Sciences Upper Austria, [Campus Hagenberg](https://www.fh-ooe.at/si/))
* License: MIT

## Background
When using the remote access functionality of IoT or smart home devices, data is often transferred through external systems. For users it is unclear if the device vendor or another third party reads, stores or shares the data. Furthermore the remote access functionality in some cases requires configuration changes at the home network router. This can induce a weak point in the home network and can potentially allow attackers to access the smart home device or the whole home network.

To mitigate these privacy and security risks, I developed a concept for a secure remote access from the internet to smart home devices in my master's thesis. The technology used are Tor Onion Services, which offer some key features for a secure remote access.

To support as many devices as possible, the concept is implemented in two scenarios. The first scenario provides all the functionalities manufacturers need to integrate in their products to be able to realize a secure remote access. The second scenario describes how to implement a remote access through Tor Onion Services for existing smart home devices.

OSCAHR (**O**nion-**S**e**C**ured Sm**A**rt **H**ome **R**emote Access) is the Python implementation of this developed concept.

## Structure
OSCAHR consists of several Python modules and packages. The packages `embedded_scenario` and `proxy_scenario` contain the scenario modules. The package `common` contains several modules which are used by both scenarios.

In this repository all three packages are at the same folder level. To run OSCAHR the `common` package must be inside the scenario packages. Therefore there are symbolic links to the `common` package within the scenarios. Possibly this link has to be recreated manually. As an alternative the `common` package folder can be copied into the scenario folders.

## Scenarios
### Embedded scenario
The embedded scenario is intended for manufacturers who can integrate the concept into newly developed smart home devices. Users of such smart home devices do not need an additional device for a remote access via the Tor network and do not have to change any configurations at the home network router.

The embedded scenario package in this repository is an implementation example. It is assumed that the scenario is integrated directly into the smart home device and the client application. The manufacturer can implement different types of secure communication within the home network (for example TLS-encrypted via TCP). Since the manufacturer makes this choice and to not restrict this with the implementation, in OSCAHR communication within the home network is completely unencrypted (plain text). Furthermore within the home network no authentication between client and smart home device is realized in OSCAHR. The implementation is thus not designed for real-world use and is only intended to show how the concept works. If a manufacturer implements this concept, secure internal communication and authentication must be ensured!

### Proxy scenario
The concept of the proxy scenario can be applied to existing smart home devices. Even for smart home devices with limited resources, a remote access via the Tor network can be realized by applying the proxy scenario. This scenario requires an additional proxy device in the home network. The OSCAHR Proxy implements the remote access via the Tor network and forwards the client's requests to the smart home device in the home network. The proxy can be used for multiple clients per smart home device as well as for multiple smart home devices.

To demonstrate the basic functionality of the proxy scenario concept, in the master's thesis the range of compatible smart home devices was restricted. OSCAHR can only be used with smart home devices which are controllable via a web interface. When using the remote access, the web interface of the smart home device can be accessed via the Tor Browser. Smart home devices which are only accessible via an app are not supported by OSCAHR in the current version.

## Usage
For usage details and requirements see the README files in the scenario folders.

## Clarification
This implementation is produced independently from the Tor® anonymity software and carries no guarantee from The Tor Project about quality, suitability or anything else.

To learn more about Tor visit https://www.torproject.org/ or http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/.