# 2IC80 Zigbee Attack tool
For our final deliverable, we decided to build an attack tool that can be executed via a Command Line Interface. We settled on using Python as the programming language, as it has great API for sending and decoding packets using Scapy, as we have already seen in the course's lab sessions. As mentioned before, our tool is built on top of the ZigDiggity Zigbee hacking toolkit created by Bishop Fox. Check out ![ZigDiggity](https://github.com/BishopFox/zigdiggity). We have modified they project code to allow it to work with the Zigbee Lighting Link protocol. 

## Installation

The installation of our tool is practically the same as ZigDiggity.
Using a default install of Raspbian, perform the following steps:

* Plug your Raspbee into your Raspberry Pi
* Enable serial using the `sudo raspbi-config` command
  * Select "Advanced Options/Serial"
  * Select *NO* to "Would you like a login shell to be accessible over serial?"
  * Select *YES* to enabling serial
  * Restart the Raspberry Pi
* Install GCFFlasher available [Here](https://www.dresden-elektronik.de/funktechnik/service/download/driver/?L=1)
* Flash the Raspbee's firmware
  * `sudo GCFFlasher -f firmware/zigdiggity_raspbee.bin`
  * `sudo GCFFlasher -r`
* Install the python requirements using `pip3 install -r requirements.txt`
* Patch scapy `sudo cp patch/zigbee.py /usr/local/lib/python3.5/dist-packages/scapy/layers/zigbee.py`
* Install wireshark on the device using `sudo apt-get install wireshark`

### Hardware used for our projet

[Raspbee](https://www.dresden-elektronik.de/funktechnik/solutions/wireless-light-control/raspbee/?L=1)

* Raspberry Pi 3 B

## Usage
Our tool is a CLI and can be run using Python3:

```python3 main-cli.py```

When running with wireshark, root privileges may be required.
