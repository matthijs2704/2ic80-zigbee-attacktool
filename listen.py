#!/usr/bin/env python

from zigdiggity.interface.components.logo import Logo
from zigdiggity.interface.console import print_notify
from scapy.layers.zigbee import *
from scapy.layers.dot15d4 import *
import zigdiggity.observers.utils as observer_utils
from PyInquirer import prompt
from zigdiggity.misc.utils import NumberValidator
import argparse
import time
import signal
import os
import sys
sys.path.append(os.getcwd() + "/zigdiggity")


class ListenProg():
    def __init__(self, radio):
        self.radio = radio

    def handle_interrupt(self, signal, frame):
        global interrupted
        print_notify("Exiting the current script")
        interrupted = True

    def listen(self):
        channelAns = prompt([{
            'type': 'input',
            'name': 'channel',
            'message': 'Which channel would you like to use?',
            'validate': NumberValidator,
            'filter': lambda val: int(val)
        }])

        if "channel" in channelAns:
            self.start_listening(channelAns["channel"])

    def start_listening(self, channel):
        # if args.wireshark:
        #     observer_utils.register_wireshark(radio)
        #     print_notify("Registered Wireshark Observer")
        # if args.stdout:
        #     observer_utils.register_stdout(radio)
        #     print_notify("Registered Stdout Observer")

        self.radio.set_channel(channel)

        print_notify("Listening to channel %d" % self.radio.get_channel())

        signal.signal(signal.SIGINT, self.handle_interrupt)
        interrupted = False

        while not interrupted:
            self.result = self.radio.receive()
