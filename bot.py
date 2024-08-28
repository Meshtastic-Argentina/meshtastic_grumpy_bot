#!python3
""" 
BairesMesh grumpy chat BOT
"""
import sys
import logging
import time
import random
import traceback
import re
from datetime import datetime
from os import path

# Changelog
#
# v1.6:
# * Added other apps to output.
# * Enhanced output format and alignment.
# * Moved phrases to a different file.
# * Fixed missing import.
#
# v1.5:
# * Added PAXcounter and other node attributes to output.
# * Other code changes.
#
# v1.4:
# * Added BLE device support.
# * Updated documentation.
#
# v1.3:
# * Added /status as an information command.
# * Removed packet dump when /info or /status is requested.
#
# v1.2:
# * Added Waypoint information.
# * Removed Range Test packet dump.
# * Minor code changes.
#
# v1.1:
# * Added support for Meshtastic devices connected over Serial.
# * Added more detailed /info output.
# * Added missing comma in phrases list merging two phrases into one.
#
# v1.0:
# * Initial version
#

__description__ = "BairesMesh grumpy chat BOT"
__version__ = 1.6

from phrases import *
try:
    import pyqrcode # type: ignore[import-untyped]
    from google.protobuf.json_format import MessageToDict
    from pubsub import pub # type: ignore[import-untyped]

    import meshtastic.test
    import meshtastic.util
    from meshtastic import mt_config
    from meshtastic import mesh_pb2, storeforward_pb2, channel_pb2, \
            paxcount_pb2, config_pb2, portnums_pb2, \
            remote_hardware, BROADCAST_ADDR
    from meshtastic.version import get_active_version
    from meshtastic.mesh_interface import MeshInterface
    from meshtastic.tcp_interface import TCPInterface
    from meshtastic.ble_interface import BLEInterface
    from meshtastic.serial_interface import SerialInterface

    from colorama import Fore
    from colorama import Style
except ImportError as error:
    print(f"Error : {error}")
    print("\nMake sure to run: pip install -r requirements\n")
    sys.exit(1)


test_keywords = [
        "test", "prueba", "try", "ping"]

ping_keywords = ["ping"]

saludos_keywords = ["buen", "buenos", "buenas", "hola"]

info_keywords = ["info", "status"]

last_message_time = time.time() # This way it'll take a bit to start bitching

DISRUPT_MSG_INTERVAL = 60

def get_message_for_TOD():
    current_time = datetime.now().time()
    
    if current_time >= datetime.strptime('06:00:00', '%H:%M:%S').time() and \
        current_time < datetime.strptime('12:00:00', '%H:%M:%S').time(): 
        return random.choice(saludos_de_manana)
    elif current_time >= datetime.strptime('12:00:00', '%H:%M:%S').time() and \
        current_time < datetime.strptime('18:00:00', '%H:%M:%S').time():
        return random.choice(saludos_de_tarde)
    else:
        return random.choice(saludos_de_noche)

def word_in_string(keywords, string):
    """Indicate if a word in the keywords list is included in the string."""
    for w in keywords:
        if w in string.lower():
            return True
    return False


def handle_telemetry_packet(packet, interface):
    """Handle incoming TELEMETRY packet."""
    pass

def handle_position_packet(packet, interface):
    """Handle incoming POSITION packet."""
    pass

def handle_message_packet(packet, interface):
    """Handle incoming MESSAGE packet."""
    from_id = packet["fromId"]
    frm = interface.nodes[from_id]["user"]["shortName"]

    #print("--->%r<---" % packet)
    decoded = packet.get("decoded")
    msg = decoded["text"]
    reply = None

    if msg is None or len(msg) == 0:
        return

    ch_idx = packet.get("channel", 0)
    logging.info(f"{Fore.MAGENTA}\tMessage{Style.RESET_ALL} [chan {ch_idx}] : {msg}")

    # Reply to greetings messages
    if word_in_string(saludos_keywords, msg.split()[0]):
        reply = get_message_for_TOD()
    # Reply with an 'OK' to test messages
    elif word_in_string(test_keywords, msg.split()[0].lower()):
        reply = "%s OK" % msg.split()[0]
    elif msg[0] == "/":
        # Reply to specific commands
            # Reply to specific 'ping' messages
            if word_in_string(ping_keywords, msg[1 : ].lower()):
                reply = "pong"

            elif word_in_string(info_keywords, msg[1 : ]):
                # Reply to every received message with some stats
                #logging.error(f"--->{packet}<---")
                rx_snr = packet.get("rxSnr", "???")
                rx_rssi = packet.get("rxRssi", "???")
                hop_start = packet.get("hopStart", "???")
                hopLimit = packet.get("hopLimit", "???")
                epoch_time = packet.get("rxTime", None)
                mac_addr = packet.get('macaddr')
                if mac_addr:
                    mac_addr = "MAC : "
                    mac_addr += ":".join(["%02X" % ord(x) for x in user.get("macaddr")])
                if epoch_time != None:
                    epoch_datetime = datetime.fromtimestamp(epoch_time)
                    rx_time = epoch_datetime.strftime('%H:%M:%S')
                    now = datetime.now()
                    time_difference = now - epoch_datetime
                    total_secs = time_difference.total_seconds()
                else:
                    rx_time = "???"
                    total_secs = 0.0

                #print(f"Diferencia de tiempo: {time_difference}")
                #print(f"Diferencia total en segundos: {total_seconds:.0f} segundos")
                reply = f"rxSnr : {rx_snr}  rxRSSI : {rx_rssi} " \
                        f"rxTime : {rx_time} (took {total_secs:.0f} secs)  " \
                        f"hopStart : {hop_start}  hopLimit : {hopLimit}"
                if mac_addr:
                    reply += f" - {mac_addr}"
    else:
        global last_message_time

        # Get the current time in seconds since the UNIX epoch
        current_time = time.time()

        # Check if at least N minutes have passed since the last message
        if current_time - last_message_time >= DISRUPT_MSG_INTERVAL * 60:
            reply = random.choice(insults)

            # Update the last message time to the current time
            last_message_time = current_time

    if reply is not None:
        logging.info(f"\t{Fore.GREEN}Reply : {Style.RESET_ALL}{reply}")
        r = interface.sendText(reply.format(frm=frm), channelIndex=ch_idx)
        #print(f"res {r}")

#switch_message = {
#        "TEXT_MESSAGE_APP" : handle_message_packet,
#}

def onReceive(packet, interface):
    """Callback invoked when a packet arrives"""
    try:
        #print("-"*80 + "\n" + repr(packet))
        decoded = packet.get("decoded")
        #logging.info(f"in onReceive() decoded:{decoded}")

        if decoded is None:
            return

        #print(repr(decoded))
        from_short_name = "<UNK>"
        try:
            from_id = packet["fromId"]
            from_short_name = interface.nodes[from_id]["user"]["shortName"]
        except KeyError as e:
            pass

        to_short_name = "<UNK>"
        try:
            to_id = packet["toId"]
            if to_id == BROADCAST_ADDR:
                to_short_name = "ALL"
            else:
                to_short_name = interface.nodes[to_id]["user"]["shortName"]
        except KeyError as e:
            pass

        port = decoded["portnum"]

        #logging.info(f"{Fore.GREEN}{port}{Style.RESET_ALL} \t: "
        #    f"{Fore.CYAN}{Style.BRIGHT}{from_short_name}{Style.RESET_ALL} " 
        #    f"-> {Fore.YELLOW}{Style.BRIGHT}{to_short_name}{Style.RESET_ALL}"
        #             )
        peers_data = \
                f"{Style.RESET_ALL}{Fore.CYAN}{Style.BRIGHT}{from_short_name:>6}{Style.RESET_ALL} " \
            f"-> {Fore.YELLOW}{Style.BRIGHT}{to_short_name}{Style.RESET_ALL}"

        #if decoded["portnum"] != "TEXT_MESSAGE_APP"":
        #    return


        if port == "TEXT_MESSAGE_APP":
            # Text message
            #payload = decoded['payload_utf8']
            mode = "Text message"
            logging.info(
                    f"{Fore.WHITE}{Style.BRIGHT}{mode:<15} "
                    f"{peers_data:<45}{Style.RESET_ALL} ")
            handle_message_packet(packet, interface)

        elif port == "RANGE_TEST_APP":
            #logging.error(f"---->{decoded}<---")
            mode = "Range Test"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
            pass

        elif port == "DETECTION_SENSOR_APP":
            logging.error(f"---->{decoded}<---")
            mode = "Detection Sensor"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
            pass

        elif port == "POSITION_APP":
            # GPS data
            position = decoded['position']
            latitude = position.get('latitude')
            longitude = position.get('longitude')
            altitude = position.get('altitude')
            mode = "Position"
            logging.info(f"{Fore.BLUE}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                         f"Latitude: {latitude}, Longitude: {longitude}, "
                         f"Altitude: {altitude}")

        elif port == "NODEINFO_APP":
            #logging.error(f"---->{decoded}<---")
            user = decoded.get("user", None)
            mode = "Node Info"
            if user is None:
                logging.warning(
                    f"{Fore.YELLOW}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                    "Not available")
                return

            long_name = user.get("longName", "???")
            short_name = user.get("shortName", "???")
            hw_model = user.get("hwModel", "???")
            role = user.get("role", "???")
            if user.get('macaddr'):
                mac_addr = "MAC : "
                mac_addr += ":".join(["%02X" % ord(x) for x in user.get("macaddr")])
            logging.info(
                f"{Fore.YELLOW}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                f"Name : {long_name} ({short_name}) "
                f"Hw model : {hw_model} Role : {role} "
                f"{mac_addr}")
            pass
        elif port == "ADMIN_APP":
            mode = "Admin"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
        elif port == "ROUTING_APP":
            #logging.error(f"---->{decoded}<---")
            mode = "Routing"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
        elif port == "TELEMETRY_APP":
            mode = "Telemetry"
            #
            # Telemetry data
            #
            # device_metrics {
            #     battery_level: 92
            #     voltage: 4.087
            #     channel_utilization: 6.49166679
            #     air_util_tx: 5.47711086
            # }
            #
            telemetry = decoded['telemetry']
            #logging.info(f"Telemetry : {telemetry}")

            if 'deviceMetrics' in telemetry:
                metrics = telemetry.get('deviceMetrics')
                battery_level = metrics.get('batteryLevel', "???")
                voltage = metrics.get('voltage', "???")
                channel_utilization = metrics.get('channelUtilization', "???")
                air_util_tx = metrics.get('airUtilTx', "???")

                logging.info(f"{Fore.MAGENTA}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                             f"Voltage: {voltage}V ({battery_level}%), "
                             f"Channel util.: {channel_utilization}"
                             )

            if 'environmentMetrics' in telemetry:
                # environment_metrics {
                #  temperature: 22.9
                #  barometric_pressure: 1015.01
                #}
                metrics = telemetry.get('environmentMetrics')
                temperature = metrics.get('temperature', "???")
                barometric_pressure = metrics.get('barometricPressure', "???")

                logging.info(f"{Fore.MAGENTA}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                             f"Temp: {temperature}C , Barometric Press. {barometric_pressure}{Style.RESET_ALL}"
                             )

        elif port == "REMOTE_HARDWARE_APP":
            logging.error(f"---->{decoded}<---")
            mode = "Remote HW"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
        elif port == "SIMULATOR_APP":
            logging.error(f"---->{decoded}<---")
            mode = "Simulator"
            logging.info(f"{Fore.CYAN}{Style.BRIGHT}{mode:<15} {peers_data:<45}")
        elif port == "TRACEROUTE_APP":
            mode = "Traceroute"
            want_response = decoded.get("wantResponse", "???")
            logging.info(f"{Fore.RED}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                         f"Want Response: {want_response}"
                         )
        elif port == "WAYPOINT_APP":
            # 
            # ---->{'portnum': 'WAYPOINT_APP', 'payload': b'\x08\xe9\x98\xf9\xc7\r\x15~\x96f\xeb\x1d\xb2\xa5.\xdd \xff\xff\xff\xff\x072\nAeroparque:\x10prueba waypoints', 'waypoint': {'id': 3640544361, 'latitudeI': -345598338, 'longitudeI': -584145486, 'expire': 2147483647, 'name': 'Aeroparque', 'description': 'prueba waypoints', 'raw': id: 3640544361
            #latitude_i: -345598338
            #longitude_i: -584145486
            #expire: 2147483647
            #name: "Aeroparque"
            #description: "prueba waypoints"
            #}}<---
            #logging.error(f"---->{decoded}<---")
            waypoint = decoded.get('waypoint', None)
            if waypoint == None:
                logging.error("No waypoint information available.")
                logging.error(f"---->{decoded}<---")
                return

            latitude = waypoint.get('latitude_i', "???")
            longitude = waypoint.get('longitude_i', "???")
            name = waypoint.get('name', "???")
            description = waypoint.get('description', "???")
            mode = "Waypoint"
            logging.info(f"{Fore.RED}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                    f"Name: {name} (desc : {description}) "
                    f"Latitude: {latitude}, Longitude: {longitude}, "
                    )
        elif port == "PAXCOUNTER_APP":
            #logging.error(f"---->{decoded}<---")
            mode = "Paxcounter"
            message = paxcount_pb2.Paxcount()
            payload_bytes = packet['decoded'].get('payload', b'')
            message.ParseFromString(payload_bytes)
            wifi = message.wifi
            ble = message.ble
            uptime = message.uptime
            logging.info(f"{Fore.RED}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                    f"    Wifii : wifi "
                    f"    BLE : ble "
                    f"    Uptime : uptime")
        elif port == "STORE_FORWARD_APP":
            logging.error(f"---->{decoded}<---")
            pass
        elif port == "NEIGHBORINFO_APP":
            #logging.error(f"---->{decoded}<---")
            mode = "Neighbor"
            message = mesh_pb2.NeighborInfo()
            payload_bytes = packet['decoded'].get('payload', b'')
            message.ParseFromString(payload_bytes)
            logging.info(f"{Fore.GREEN}{Style.BRIGHT}{mode:<15} {peers_data:<45}{Style.RESET_ALL} "
                    f"Node ID: {message.node_id} / {idToHex(message.node_id)} "
                    f"Last Sent By ID: {message.last_sent_by_id} "
                    f"Node Broadcast Interval : {message.node_broadcast_interval_secs} secs."
                    "Neighbors:")
            for neighbor in message.neighbors:
                logging.info(f"    Neighbor ID: {neighbor.node_id} / {idToHex(neighbor.node_id)} "
                    f"SNR: {neighbor.snr}")
        elif port == "MAP_REPORT_APP":
            logging.error(f"---->{decoded}<---")
            pass

        if 'payload_bytes' in decoded:
            # Binary data
            payload = decoded['payload_bytes']
            logging.info(f"\tBinary data {peers_data:<45} {payload}")
        elif 'data' in decoded:
            # Generic data message
            data = decoded['data']
            sensor_type = data.get('sensorType')
            value = data.get('value')
            logging.info(f"\tData message {peers_data:<45} Sensor Type: {sensor_type}, Value: {value}")
        #else:
        #    logging.info(f"\tUnknown packet from {from_short_name} to {to_short_name}")

    except KeyError as ex:
        logging.error(f"Error {ex}")
        traceback_str = traceback.format_exc()
        logging.error(f"Traceback :\n{traceback_str}")

    except TypeError as ex:
        logging.error(f"Error {ex}")
        traceback_str = traceback.format_exc()
        logging.error(f"Traceback :\n{traceback_str}")

def idToHex(nodeId): 
    return '!' + hex(nodeId)[2:]

def onConnection(interface, topic=pub.AUTO_TOPIC):  # pylint: disable=W0613
    """Callback invoked when we connect/disconnect from a radio"""
    print(f"Connection changed: {topic.getName()}")

def subscribe():
    """Subscribe to the topics the user probably wants to see, prints output to stdout"""
    pub.subscribe(onReceive, "meshtastic.receive")

def print_nodes(client):
    # Obtain and display a list of known nodes.
    for i, (node_id, node) in enumerate(client.nodes.items(), start=1):
        print(f"#{i}, Nodo ID: {node_id}, Nombre: {node['user']['longName']},")

def start(client):
    """..."""
    #print_nodes(client)
    subscribe()

    while True:
        time.sleep(3)
        if client.isConnected == False:
            logging.critical("!!!! Client disconnected !!!!")
            logging.error("--->%r<---" % client)
            break

def contains_ip(string):
    """Find IPv4 address inside a string."""
    # regex for IPv4 address
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    match = re.search(ip_regex, string)
    return bool(match)

def main():
    """Main routine."""
    logfile = None
    logging.basicConfig(
        level=logging.INFO,
        format = 
            f"{Fore.WHITE}{Style.DIM}%(asctime)s{Style.RESET_ALL} "
            f"{Fore.GREEN}{Style.BRIGHT}[%(levelname)s]{Style.RESET_ALL} %(message)s",
        datefmt='%H:%M:%S'
    )

    device = sys.argv[1]
    logging.info(f"{Fore.MAGENTA}{Style.BRIGHT}{__description__} v{__version__}{Style.RESET_ALL}")

    while True:
        try:
            logging.info(f"Connecting to device {Fore.GREEN}{Style.BRIGHT}{device}{Style.RESET_ALL}")
            if path.exists(device):
                client = SerialInterface(devPath=device)
            else:
                if contains_ip(device):
                    client = TCPInterface(device, debugOut=logfile, noProto=None)
                else:
                    client = BLEInterface(device)

            start(client)
        except KeyboardInterrupt as ex:
            logging.warning(f"Leaving (CTRL-C pressed)...")
            break
        except Exception as ex:
            logging.error(f"Disconnected from device {device}. Reson : {ex}")
            logging.error("-" * 40)
            time.sleep(1)

    client.close()

if __name__ == "__main__":
    main()
