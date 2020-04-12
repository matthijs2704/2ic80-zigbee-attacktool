# 2IC80 Zigbee Attack tool
In this project, we have researched the Zigbee protocol and specifically on how this is implemented in IKEA Trådfri (Swedish for 'wireless'). IKEA Trådfri is the smart home lighting system created by IKEA, which uses the Zigbee Lighting Link protocol for communication between the many smart devices IKEA sells. IKEA now provides lights, smart sockets, blinds, and even their audio system as part of their Home Smart ecosystem. Our goal for this project was to gain access to this Zigbee network and then to overtake the communication between the gateway and the lights. This would allow us to control the lights and be able to effectively DoS the system and block the user's control. 

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

## Features
The attack we have developed consists of four parts, the scanning of Zigbee channels, the listening to a Zigbee channel, the extraction of the network encryption key, and lastly the spoofing of the gateway. We will explain these tools separately below.

Scanning channels
-----------------

The first option in the aforementioned CLI is to scan channels for networks. When this option is chosen our program starts a function that scans the channels ranging from channel 11 through 26. These channels are in the 2.4GHz band, as well as WiFi networks. Because of this overlap, there is a chance of interference between the channels. We found that the Alliance has defined the following channels as primary: 11, 15, 20 and 25. This can be explained by the interference with WiFi.

![Figure 2: The 2.4GHz band. The channels in red and the WiFi channels in blue (1), green (6), and yellow (11).@Zigbee [@vs; @WiFi]<span data-label="fig:Zigbee vs WiFi"></span>](Images/ZigBeeChannels.png){width="columnwidth"}

As shown in the figure above, the channels 15, 20, 25, and 26 have less interference than the other channels. This explains why the channels 15, 20, and 25 are primarily used. The reason that channel 26 is rarely used is that many devices do not support it@Zigbee [@vs; @WiFi]. However, channel 11 is the primary channel of and hence the probability that this channel is already in use is large. In addition to this, the interference on this channel is large if WiFi channel 1 is in use.
One should note that a channel can be used by multiple different networks, or Personal Area Networks (PANs). Each of these networks has a unique identifier. When the gateway is set-up, it generates a new network with a unique PAN ID. Other devices are then able to scan for networks and join the one with this PAN ID. More about the fetching of this PAN ID will follow in Section [Spoof]

Listening to channel
--------------------

After having scanned the available channels on the spectrum, it is possible to select a channel for listening to the traffic sent on this channel. The data is reported in the console itself. This data is the raw, encrypted, data on the channel. However, it is far more useful to use the option of opening Wireshark to monitor the traffic. If the network key is known, it can be entered in the preferences of Wireshark. This results in Wireshark decrypting the data as it comes in. If only the ZLL master/commissioning key is entered in the list. Wireshark will try to decrypt this data. When it finds the network encryption key in the data, from that moment on, it will decrypt all the data as well.
As already said, one channel can be used by multiple PANs, therefore one may still see encrypted data, as the network key for this other PAN would be different.

Key extraction
--------------

All data of the Zigbee protocol is encrypted using AES-128-CCM. To be able to communicate on the network, we need to figure out what the encryption key is. In our tool, we have created a function that listens for the data on the channel and tries to decrypt the commissioning key using the ZLL master key (and the ZLL commissioning key). If this succeeds, then it will print the found encryption key to the console, so it can be used later in our spoofing attack.

Spoofing the gateway
--------------------

The last feature we have developed in our tool is to spoof commands from the gateway. Interesting to know is that the only counter we have to keep track of is the one used for the encryption. The other sequence numbers (in the 802.15.4 layer, network layer and the ZCL layer) appear to be in there, per specification, but not used in the implementation, as we are able to choose those sequence numbers randomly.

### Controlling the lights

Our tool provides a way to toggle a light, turn off a light and turn on a light. It sends the packets just like the gateway would do. Therefore the lights do not know whether the command originated from the gateway or our attack tool. Our tool provides a way to automatically discover the devices on the network and set the attack parameters using the GUI or one can enter the parameters manually. To do a successful spoofing attack, we need to know the gateway ID, target ID and the network encryption key. The tool will then automatically monitor for the frame counter, used in the encryption. After it has acquired this, it will send the specified amount of packets to the target.

### Denial of Service

The attack as specified above, can be used to effectively DoS the smart lighting system, as it allows to specify how many packets should be sent. If we set this to a relatively large value, the tool will keep sending the specified command to the light and therefore override any user input from the app or the remote control.

### Factory Reset

Our tool can also send a factory reset command in the same way that the commands for the controlling of the lights are sent. However, this functionality also required a leave request to be sent before the factory reset would be performed. These packets will tell the light to leave the network and do a factory reset respectively. The leave request required us to use a Device Profile packet, as it is part of a different specification of Zigbee. Since Scapy, the underlying packet building and parsing tool, does not contain a class to handle these packets we had to patch Scapy to add this ourselves. After the leave request is sent, we command the target to do a factory reset. After this attack has been performed, the targeted device will be removed from the network and will need to be reconnected manually by the user.
