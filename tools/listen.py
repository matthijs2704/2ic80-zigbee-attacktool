#!/usr/bin/env python

from zigdiggity.interface.console import print_notify
from PyInquirer import prompt
from zigdiggity.misc.utils import NumberValidator


class ListenProg():
    def __init__(self, radio):
        self.radio = radio

    def listen(self):
        channelAns = prompt([{
            'type': 'input',
            'name': 'channel',
            'message': 'Which channel would you like to use?',
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
        # if args.stdout:
        #     observer_utils.register_stdout(radio)
        #     print_notify("Registered Stdout Observer")

        self.radio.set_channel(channel)

        print_notify("Listening to channel %d" % self.radio.get_channel())

        signal.signal(signal.SIGINT, self.handle_interrupt)
        interrupted = False

        while True:
            self.result = self.radio.receive()
        return True
