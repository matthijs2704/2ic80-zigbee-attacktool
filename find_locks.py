#!/usr/bin/env python

from __future__ import print_function, unicode_literals
from PyInquirer import prompt, print_json
from PyInquirer import Validator, ValidationError

import os
import sys
sys.path.append(os.getcwd() + "/zigdiggity")
import pprint
import time
import argparse
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

from zigdiggity.radios.raspbee_radio import RaspbeeRadio
from zigdiggity.radios.observer_radio import ObserverRadio
from zigdiggity.observers.wireshark_observer import WiresharkObserver
from zigdiggity.interface.console import *
from zigdiggity.interface.components.logo import Logo
import zigdiggity.crypto.utils as crypto_utils
from zigdiggity.misc.actions import *

class NumberValidator(Validator):
    def validate(self, document):
        try:
            int(document.text)
        except ValueError:
            raise ValidationError(
                message='Please enter a number',
                cursor_position=len(document.text))  # Move cursor to end
             
logo = Logo()
logo.print()

print_info("Welcome to the Zigbee Lighting Link (Ikea Tradfri) Hacking tool!")
print_info("By group 102 for Lab on offenive Computer Security.")
questions = [
    {
        'type': 'list',
        'name': 'command',
        'message': 'Choose somtething to do',
        'choices': [
            '1. Scan for Zigbee Networks', 
            '2. Extract key on device join', 
            '3. Spoof the gateway (toggle light)'
            ],
    },
    {
        'type': 'input',
        'name': 'channel',
        'message': 'Enter the Zigbee Channel to use:',
        'validate': NumberValidator,
        'filter': lambda val: int(val)
    },
    {
        'type': 'confirm',
        'name': 'wireshark',
        'message': 'Use Wireshark?',
        'default': False,
    }
]

answers = prompt(questions)
print_json(answers)  # use the answers as input for your app

hardware_radio = RaspbeeRadio(args.device)
radio = ObserverRadio(hardware_radio)

if args.wireshark:
    wireshark = WiresharkObserver()
    radio.add_observer(wireshark)

radio.set_channel(args.channel)

print_notify("Sending beacon on on channel %d" % args.channel)

panid = None
extended_panid = None

coordinators = dict()

extended_panids = dict()
last_sequence_number = dict()
if panid is not None:
    print_notify("Looking at PAN ID 0x%04x for lights" % panid)
else:
    print_notify("Looking for lights on the current channel")
print_info("Monitoring the network for an extended period")
timer = Timer(17)
traffic_counter = 0
radio.receive()
radio.send_and_retry(beacon_request(random.randint(0,255)))
while not timer.has_expired():
    frame = radio.receive()
    if frame is not None and not is_beacon_request(frame):
        traffic_counter+=1
    if is_beacon_response(frame) and (panid is None or get_pan_id(frame)==panid):
        pan = get_pan_id(frame)
        source=get_source(frame)
        if not pan in coordinators.keys():
            print_info("Finding coordinator on 0x%04x" % pan)
            coord_addr = find_coord_addr_by_panid(radio, pan)
            coordinators[pan] = coord_addr
            extended_panids[pan] = frame[ZigBeeBeacon].extended_pan_id
            print_info("Coordinator of 0x%04x is possibly 0x%04x" % (pan, coord_addr))
            last_sequence_number[pan] = dict()
        if not source in last_sequence_number[pan]:
            last_sequence_number[pan][source]=-1
        if last_sequence_number[pan][source]!=frame[Dot15d4FCS].seqnum:
            last_sequence_number[pan][source]=frame[Dot15d4FCS].seqnum
    
    if timer.time_passed() > 5 and traffic_counter==0:
        print_info("No traffic observed for 5 seconds, giving up")
        break

print (coordinators)
print (extended_panids)
print (last_sequence_number)
radio.off()
