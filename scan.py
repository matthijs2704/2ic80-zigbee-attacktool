#!/usr/bin/env python
import os
import sys
sys.path.append(os.getcwd() + "/zigdiggity")

import time
from tqdm import tqdm

from zigdiggity.radios.raspbee_radio import RaspbeeRadio
from zigdiggity.radios.observer_radio import ObserverRadio
import zigdiggity.observers.utils as observer_utils
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from zigdiggity.interface.console import print_notify, print_info
from zigdiggity.misc.timer import Timer
from zigdiggity.interface.colors import *

def scanChannels(hardware_radio, radio):

    #CHANNELS = [14,15,16,17,18,19,20,21,22,23,24,25,26]
    CHANNELS = [11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26]
    pbar = tqdm(CHANNELS)
    
    channels_in_use = []
    for channel in pbar:
        radio.set_channel(channel)

        pbar.set_description(Color.s("{.} Listening to channel %d" % radio.get_channel()))

        timer = Timer(10)
        while(not timer.has_expired()):    
            frame = radio.receive()
            if frame is not None:
                tqdm.write(Color.s("{+} Found traffic on channel %d" % channel))
                channels_in_use.append(channel)
                time.sleep(1)
                break
                
        pbar.update()
    return channels_in_use
