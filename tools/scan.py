#!/usr/bin/env python
import time

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

from tqdm import tqdm
from zigdiggity.interface.colors import Color
from zigdiggity.misc.timer import Timer


class ScanTool(object):
    def __init__(self, radio):
        self.radio = radio

    def scanChannels(self):

        #CHANNELS = [14,15,16,17,18,19,20,21,22,23,24,25,26]
        CHANNELS = [11, 12, 13, 14, 15, 16, 17,
                    18, 19, 20, 21, 22, 23, 24, 25, 26]
        pbar = tqdm(CHANNELS)

        channels_in_use = []
        for channel in pbar:
            self.radio.set_channel(channel)

            pbar.set_description(
                Color.s("{.} Listening to channel %d" % self.radio.get_channel()))

            timer = Timer(10)
            while(not timer.has_expired()):
                frame = self.radio.receive()
                if frame is not None:
                    tqdm.write(
                        Color.s("{+} Found traffic on channel %d" % channel))
                    channels_in_use.append(channel)
                    time.sleep(1)
                    break

            pbar.update()
        return channels_in_use
