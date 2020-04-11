#!/usr/bin/env python

from __future__ import print_function, unicode_literals

import argparse
import pprint
import sys
import time

import zigdiggity.crypto.utils as crypto_utils
from PyInquirer import ValidationError, Validator, print_json, prompt
from zigdiggity.interface.components.logo import Logo
from zigdiggity.interface.console import *
from zigdiggity.misc.actions import *
from zigdiggity.observers.wireshark_observer import WiresharkObserver
from zigdiggity.packets.dot15d4 import is_data_frame
from zigdiggity.radios.observer_radio import ObserverRadio
from zigdiggity.radios.raspbee_radio import RaspbeeRadio


RESPONSE_TIME_LIMIT = 1  # 1s
OBSERVATION_TIME = 30  # 30s
NUMBER_OF_ATTEMPTS = 3
THRESHOLD_VARIANCE = 0.75
MIN_FREQUENCY = 0.1


def findLights(radio, channel):
    radio.set_channel(channel)

    print_notify("Sending beacon on on channel %d" % radio.get_channel())

    result = []
    trackers = dict()
    last_sequence_number = dict()
    print_notify("Looking for lights on the current channel")
    print_info("Monitoring the network for an extended period")
    timer = Timer(17)
    traffic_counter = 0
    while not timer.has_expired():
        frame = radio.receive()
        if frame is not None and not is_beacon_request(frame):
            traffic_counter += 1
        if is_data_frame(frame):
            pan = get_pan_id(frame)
            source = get_source(frame)
            if not pan in trackers.keys():
                trackers[pan] = dict()
                last_sequence_number[pan] = dict()
            if not source in trackers[pan].keys():
                trackers[pan][source] = TrackWatch()
                last_sequence_number[pan][source] = -1
            if last_sequence_number[pan][source] != frame[Dot15d4FCS].seqnum:
                trackers[pan][source].click()
                last_sequence_number[pan][source] = frame[Dot15d4FCS].seqnum

        if timer.time_passed() > 15 and traffic_counter == 0:
            print_info("No traffic observed for 15 seconds, giving up")
            break
    print(trackers.keys())
    print(last_sequence_number)

    gateways = dict()
    for pan in trackers:
        min_var = 0
        max_mean = 1000
        gateway = None
        for addr in trackers[pan]:
            watch = trackers[pan][addr]
            if watch.variance() is not None and abs(watch.variance()-watch.mean()) > min_var or gateway is None:
                min_var = watch.variance()
                max_mean = watch.mean()
                gateway = addr
                result.append((pan, addr))
            print_debug("Device 0x%04x on PAN 0x%04x had variance of %f and mean of %f" % (
                addr, pan, watch.variance(), watch.mean()))

        gateways[pan] = gateway
        print_notify(
            "Device 0x%04x on PAN 0x%04x resembles a gateway" % (gateway, pan))

    result = dict()
    result[pan] = dict()
    result[pan]['devices'] = list(trackers[pan].keys())
    result[pan]['last_sequence_number'] = last_sequence_number[pan]
    result[pan]['coordinator'] = gateways[pan]
    print(result)
    return result
    # result[pan]['extended_panid'] = extended_panids[pan]
    # return result

    # print_json(answers)  # use the answers as input for your app
    # print (coordinators)
    # print (extended_panids)
    # print (last_sequence_number)
    # radio.off()
