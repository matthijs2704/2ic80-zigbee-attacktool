#!/usr/bin/env python

from __future__ import print_function, unicode_literals
from PyInquirer import prompt
from PyInquirer import Validator, ValidationError

import os
import sys
# sys.path.append(os.getcwd() + "/zigdiggity")

import signal
import sys

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

from zigdiggity.radios.raspbee_radio import RaspbeeRadio
from zigdiggity.radios.observer_radio import ObserverRadio
from zigdiggity.observers.wireshark_observer import WiresharkObserver
from zigdiggity.interface.console import print_info
from zigdiggity.interface.components.logo import Logo
from zigdiggity.misc.actions import *

from tools.scan import ScanTool
from tools.key_extract import KeyExtractor
from tools.spoofgw_attack import SpoofAttack
from tools.listen import ListenProg


def signal_handler(signal, frame):
    print_info("[Cleanup] Turning radio off...")
    radio.off()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


class NumberValidator(Validator):
    def validate(self, document):
        try:
            int(document.text)
        except ValueError:
            raise ValidationError(
                message='Please enter a number',
                cursor_position=len(document.text))  # Move cursor to end


def clear(): return os.system('clear')


clear()

print("\n")

logo = Logo()
logo.print()

print_info("Welcome to the Zigbee Lighting Link (Ikea Tradfri) Hacking tool!")
print_info("By group 102 for Lab on offenive Computer Security.")
wireshark = None

hardware_radio = RaspbeeRadio("/dev/ttyS0")
radio = ObserverRadio(hardware_radio)


while True:
    questions = [
        {
            'type': 'list',
            'name': 'program',
            'message': 'What would you like to do?',
            'choices': [
                '1. Scan Zigbee channels for Networks',
                '2. Listen on ZigBee channel',
                '3. Extract key on device join',
                '4. Spoof the gateway'
            ],
        },
        {
            'type': 'confirm',
            'name': 'wireshark',
            'message': 'Would you like to open Wireshark?',
            'default': False,
            'when': lambda ans: wireshark == None
        }
    ]

    answers = prompt(questions)

    if "wireshark" in answers:
        wireshark = answers["wireshark"]

        if wireshark:
            wireshark = WiresharkObserver()
            radio.add_observer(wireshark)

    if answers["program"].startswith("1."):
        prog = ScanTool(radio)
        prog.scanChannels()
    elif answers["program"].startswith("2."):
        prog = ListenProg(radio)
        prog.listen()
    elif answers["program"].startswith("3."):
        prog = KeyExtractor(radio)
        prog.extractKey()
    elif answers["program"].startswith("4."):
        prog = SpoofAttack(radio)
        prog.doGWSpoofAttack()
