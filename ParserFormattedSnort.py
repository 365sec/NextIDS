import sys
import signal
import struct
import os
import threading
import stat
import socket
import zlib
import re
import multiprocessing
from binascii import hexlify, unhexlify
from optparse import OptionParser
from time import time, localtime, mktime, strptime, strftime, sleep
from base64 import b64encode
import glob
from Event import Event
from syslog_log import *
SNORT_FILE_HEADER_SIZE = 8
UNIFIED2_EVENT = 1
UNIFIED2_PACKET = 2
UNIFIED2_IDS_EVENT = 7
UNIFIED2_IDS_EVENT_IPV6 = 72
UNIFIED2_IDS_EVENT_MPLS = 99
UNIFIED2_IDS_EVENT_IPV6_MPLS = 100
UNIFIED2_IDS_EVENT_VLAN = 104
UNIFIED2_IDS_EVENT_IPV6_VLAN = 105
UNIFIED2_EXTRA_DATA = 110
UNIFIED2_IDS_EVENT_NG = 207
UNIFIED2_IDS_EVENT_IPV6_NG = 208
EVENT_TYPE_EXTRA_DATA = 4
TOTAL = 1111
ETHERNET_TYPE_IP = 2048
ETHERNET_TYPE_IPV6 = 34525
ETHERNET_TYPE_8021Q = 33024
ETHERNET_TYPE_PPPOES = 34916

class SnortIDSEvent(object):
    IDS_EVENT_ATTRS = ['sensor_id',
     'event_id',
     'event_second',
     'event_microsecond',
     'signature_id',
     'generator_id',
     'signature_revision',
     'classification_id',
     'priority_id',
     'ip_source',
     'ip_destination',
     'sport_itype',
     'dport_icode',
     'protocol',
     'impact_flag',
     'impact',
     'blocked',
     'raw_data',
     'timestamp']
    IDS_EVENT_BASE64 = ['raw_data']

    def __init__(self):
        self.ids_event = {}

    def __setitem__(self, key, value):
        if key in self.IDS_EVENT_ATTRS:
            self.ids_event[key] = value

    def __getitem__(self, key):
        return self.ids_event.get(key, None)

    def __repr__(self):
        str = ''
        for attr in self.IDS_EVENT_ATTRS:
            if self[attr]:
                str += ' %s="%s"' % (attr, self[attr])

        return str + '\n'


class SnortUnpack():
    ids_events_lock = threading.RLock()
    ids_events = {}
    purge_thread = None
    purge_thread_started = False
    keep_purgin = False

    def __init__(self):
        print 'Snort Unpacker...'

    @staticmethod
    def get_UNIFIED2_EVENT(data):
        info('No information available for UNIFIED2_EVENT')

    @staticmethod
    def get_UNIFIED2_IDS_EVENT_MPLS(data):
        info('No information available for UNIFIED2_IDS_EVENT_MPLS')

    @staticmethod
    def get_UNIFIED2_IDS_EVENT_IPV6_MPLS(data):
        info('No information available for get_UNIFIED2_IDS_EVENT_IPV6_MPLS')

    @staticmethod
    def get_EVENT_TYPE_EXTRA_DATA(data):
        info('No information available for EVENT_TYPE_EXTRA_DATA')

    @staticmethod
    def get_Unified2IDSEventNG(data):
        info('Not information yet')

    @staticmethod
    def get_Unified2IDSEventIPv6_NG(data):
        info('Not information yet')

    @staticmethod
    def get_Unified2IDSEvent(data):
        sensor_id, event_id, event_second, event_microsecond, signature_id, generator_id, signature_revision, classification_id, priority_id, source_ip, destination_ip, sport_itpye, dport_icode, protocol, impact_flag, impact, blocked, mpls_label, vlanid, pad = struct.unpack('!IIIIIIIIIIIHHBBBBIHH', data)
        sip_int = int(source_ip)
        dip_int = int(destination_ip)
        source_ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(sip_int)))
        dest_ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(dip_int)))
        ev = SnortIDSEvent()
        ev['raw_data'] = hexlify(data)
        ev['sensor_id'] = sensor_id
        ev['event_id'] = event_id
        ev['event_second'] = event_second
        ev['event_microsecond'] = event_microsecond
        ev['signature_id'] = signature_id
        ev['generator_id'] = generator_id
        ev['signature_revision'] = signature_revision
        ev['classification_id'] = classification_id
        ev['priority_id'] = priority_id
        ev['ip_source'] = source_ip_str
        ev['ip_destination'] = dest_ip_str
        ev['sport_itype'] = sport_itpye
        ev['dport_icode'] = dport_icode
        ev['protocol'] = protocol
        ev['impact_flag'] = impact_flag
        ev['impact'] = impact
        ev['blocked'] = blocked
        ev['timestamp'] = time()
        SnortUnpack.ids_events_lock.acquire()
        SnortUnpack.ids_events[event_id] = ev
        SnortUnpack.ids_events_lock.release()

    @staticmethod
    def get_Unified2IDSEventIPv6(data):
        sensor_id, event_id, event_second, event_microsecond, signature_id, generator_id, signature_revision, classification_id, priority_id = struct.unpack('!IIIIIIIII', data[0:36])
        str_ipv6_source = socket.inet_ntop(socket.AF_INET6, data[36:52])
        str_ipv6_dest = socket.inet_ntop(socket.AF_INET6, data[52:68])
        source_port_itype, dest_port_itype, protocol, impact_flag, impact, blocked, mpls_label, vlan_id, pad2 = struct.unpack('!HHBBBBIHH', data[68:])
        ev = SnortIDSEvent()
        ev['raw_data'] = hexlify(data)
        ev['sensor_id'] = sensor_id
        ev['event_id'] = event_id
        ev['event_second'] = event_second
        ev['event_microsecond'] = event_microsecond
        ev['signature_id'] = signature_id
        ev['generator_id'] = generator_id
        ev['signature_revision'] = signature_revision
        ev['classification_id'] = classification_id
        ev['priority_id'] = priority_id
        ev['ip_source'] = str_ipv6_source
        ev['ip_destination'] = str_ipv6_dest
        ev['sport_itype'] = source_port_itype
        ev['dport_icode'] = dest_port_itype
        ev['protocol'] = protocol
        ev['impact_flag'] = impact_flag
        ev['impact'] = impact
        ev['blocked'] = blocked
        ev['timestamp'] = time()
        SnortUnpack.ids_events_lock.acquire()
        SnortUnpack.ids_events[event_id] = ev
        SnortUnpack.ids_events_lock.release()

    @staticmethod
    def decodeIPPacket(packet):
        version_ihl, type_of_service, total_length, identification, flags_offset, ttl, protocol, header_checksum, source_ip, destination_ip = struct.unpack('>BBHHHBBHII', packet[0:20])
        header_len = version_ihl & 15
        offset_to_payload = header_len * 32 / 8
        payload = packet[offset_to_payload:]
        end_payload = ''
        if protocol == socket.IPPROTO_ICMP:
            icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])
            end_payload = payload[8:]
        elif protocol == socket.IPPROTO_TCP:
            if len(payload) >= 20:
                source_port, destination_port, seq_number, ack_number, tcp_offset_flags, tcp_checksum, tcp_urgenpointer = struct.unpack('>HHIIIHH', payload[:20])
                tcp_header_size = ((tcp_offset_flags & 4026531840L) >> 28) * 4
                data_offset = tcp_header_size
                if len(payload) > data_offset:
                    end_payload = payload[data_offset:]
                else:
                    end_payload = ''
            else:
                end_payload = ''
        elif protocol == socket.IPPROTO_UDP:
            end_payload = payload[8:]
        else:
            end_payload = ''
        return end_payload

    @staticmethod
    def decodeIPV6Packet(packet):
        ipv6_first_word, ipv6_payload_legth, ipv6_next_header, ipv6_hoplimit = struct.unpack('>IHBB', packet[0:8])
        payload = packet[40:]
        if ipv6_next_header == socket.IPPROTO_ICMP:
            icmp_type, icmp_code, icmp_chekcsum = struct.unpack('>BBH', payload[:4])
            end_payload = payload[8:]
        elif ipv6_next_header == socket.IPPROTO_TCP:
            if len(payload) >= 20:
                source_port, destination_port, seq_number, ack_number, tcp_data_offset, tcp_window, tcp_flags, tcp_checksum, tcp_urgenpointer = struct.unpack('>HHIIBBHHH', payload[:20])
                data_offset = (tcp_data_offset & 240) >> 4
                data_offset = data_offset * 32 / 8
                if len(payload) > data_offset:
                    end_payload = payload[data_offset:]
                else:
                    end_payload = ''
            else:
                end_payload = payload[:]
        elif ipv6_next_header == socket.IPPROTO_UDP:
            end_payload = payload[8:]
        elif ipv6_next_header == socket.IPPROTO_ICMPV6:
            ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack('>BBH', payload[:4])
            end_payload = ''
            socket.IPPROTO_HOPOPTS
        elif ipv6_next_header == socket.IPPROTO_HOPOPTS:
            end_payload = ''
        else:
            warning('IPV6 - Next header not implemented: %s' % ipv6_next_header)
            end_payload = ''
        return end_payload

    @staticmethod
    def get_Serial_Unified2Packet(data, type, length):
        sensor_id, event_id, event_second, packet_second, packet_ms, linktype, packet_length = struct.unpack('!IIIIIII', data[0:28])
        if not SnortUnpack.ids_events.has_key(event_id):
            info('Pay attention! Snort packet without associated event! %s ' % event_id)
            return
        snort_packet_data = data[28:]
        eth_typ, = struct.unpack('!H', snort_packet_data[12:14])
        packet = snort_packet_data[14:]
        payload = ''
        if eth_typ == ETHERNET_TYPE_IP:
            end_payload = SnortUnpack.decodeIPPacket(packet)
        elif eth_typ == ETHERNET_TYPE_IPV6:
            end_payload = SnortUnpack.decodeIPV6Packet(packet)
        elif eth_typ == ETHERNET_TYPE_8021Q:
            vlan_header, ethstype = struct.unpack('>HH', packet[:4])
            payload = packet[4:]
            if ethstype == ETHERNET_TYPE_IP:
                end_payload = SnortUnpack.decodeIPPacket(payload)
            elif ethstype == ETHERNET_TYPE_IPV6:
                end_payload = SnortUnpack.decodeIPV6Packet(packet)
            else:
                end_payload = ''
        elif eth_typ == ETHERNET_TYPE_PPPOES:
            warning('ETHERNET_TYPE_PPPOES - Not implemented')
            end_payload = ''
        else:
            warning('ethernet_type: %s' % eth_typ)
            return
        ev = Event()
        idsev = SnortUnpack.ids_events[event_id]
        ev['plugin_id'] = str(1000 + idsev['generator_id'])
        ev['plugin_sid'] = idsev['signature_id']
        ev['src_ip'] = idsev['ip_source']
        ev['dst_ip'] = idsev['ip_destination']
        ev['src_port'] = idsev['sport_itype']
        ev['dst_port'] = idsev['dport_icode']
        ev['protocol'] = idsev['protocol']
        len_payload = len(end_payload)
        textpayload = ''
        try:
            textpayload = '%s' % end_payload
        except Exception as e:
            error('Error convertion bintoascii snort payload')
            textpayload = ''

        ev['log'] = textpayload
        len_data = len(data) - len(end_payload)
        capture = data[:]
        compress_data = zlib.compress(capture)
        ev['binary_data'] = hexlify(compress_data)
        return ev

    @staticmethod
    def get_SerialUnified2ExtraData(data):
        pass

    @staticmethod
    def get_Serial_Unified2IDSEvent_legacy(data, type, length):
        sensor_id, event_id, event_second, event_microsecond, signature_id, generator_id, signature_revision, classification_id, priority_id, ip_source, ipdestination, sport_itype, dport_icode, protocol, impact_flag, impact, blocked = struct.unpack('!IIIIIIIIIIIHHBBBB', data)
        sip_int = int(ip_source)
        dip_int = int(ipdestination)
        source_ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(sip_int)))
        dest_ip_str = socket.inet_ntoa(struct.pack('I', socket.htonl(dip_int)))
        ev = SnortIDSEvent()
        ev['raw_data'] = hexlify(data)
        ev['sensor_id'] = sensor_id
        ev['event_id'] = event_id
        ev['event_second'] = event_second
        ev['event_microsecond'] = event_microsecond
        ev['signature_id'] = signature_id
        ev['generator_id'] = generator_id
        ev['signature_revision'] = signature_revision
        ev['classification_id'] = classification_id
        ev['priority_id'] = priority_id
        ev['ip_source'] = source_ip_str
        ev['ip_destination'] = dest_ip_str
        ev['sport_itype'] = sport_itype
        ev['dport_icode'] = dport_icode
        ev['protocol'] = protocol
        ev['impact_flag'] = impact_flag
        ev['impact'] = impact
        ev['blocked'] = blocked
        ev['timestamp'] = time()
        SnortUnpack.ids_events_lock.acquire()
        SnortUnpack.ids_events[event_id] = ev
        SnortUnpack.ids_events_lock.release()

    @staticmethod
    def get_Serial_Unified2IDSEventIPv6_legacy(data):
        sensor_id, event_id, event_second, event_microsecond, signature_id, generator_id, signature_revision, classification_id, priority_id = struct.unpack('!IIIIIIIII', data[0:36])
        str_ipv6_source = socket.inet_ntop(socket.AF_INET6, data[36:52])
        str_ipv6_dest = socket.inet_ntop(socket.AF_INET6, data[52:68])
        source_port_itype, dest_port_itype, protocol, impact_flag, impact, blocked = struct.unpack('!HHBBBB', data[68:])
        ev = SnortIDSEvent()
        ev['raw_data'] = hexlify(data)
        ev['sensor_id'] = sensor_id
        ev['event_id'] = event_id
        ev['event_second'] = event_second
        ev['event_microsecond'] = event_microsecond
        ev['signature_id'] = signature_id
        ev['generator_id'] = generator_id
        ev['signature_revision'] = signature_revision
        ev['classification_id'] = classification_id
        ev['priority_id'] = priority_id
        ev['ip_source'] = str_ipv6_source
        ev['ip_destination'] = str_ipv6_dest
        ev['sport_itype'] = source_port_itype
        ev['dport_icode'] = dest_port_itype
        ev['protocol'] = protocol
        ev['impact_flag'] = impact_flag
        ev['impact'] = impact
        ev['blocked'] = blocked
        ev['timestamp'] = time()
        SnortUnpack.ids_events_lock.acquire()
        SnortUnpack.ids_events[event_id] = ev
        SnortUnpack.ids_events_lock.release()

    @staticmethod
    def purgeEvents():
        while SnortUnpack.keep_purgin:
            events_to_del = []
            SnortUnpack.ids_events_lock.acquire()
            for event_id, event in SnortUnpack.ids_events.iteritems():
                if time() - float(event['timestamp']) > 5:
                    events_to_del.append(event_id)

            for event_id in events_to_del:
                del SnortUnpack.ids_events[event_id]

            SnortUnpack.ids_events_lock.release()
            del events_to_del[:]
            sleep(1)

        info('ending... snort unpacker thread..')

    @staticmethod
    def startPurgeEventsThread():
        info('Starting snort  unpacker purge thread')
        if SnortUnpack.purge_thread is None:
            SnortUnpack.purge_thread_started = True
            SnortUnpack.keep_purgin = True
            SnortUnpack.purge_thread = threading.Thread(target=SnortUnpack.purgeEvents, args=())
            SnortUnpack.purge_thread.start()

    @staticmethod
    def stopPurgeEventsThread():
        SnortUnpack.keep_purgin = False


class SnortEventsParser():
    snort_events_by_type = {}
    snort_events_by_type[1] = 'UNIFIED2_EVENT'
    snort_events_by_type[2] = 'UNIFIED2_PACKET'
    snort_events_by_type[4] = 'EVENT_TYPE_EXTRA_DATA'
    snort_events_by_type[7] = 'UNIFIED2_IDS_EVENT'
    snort_events_by_type[72] = 'UNIFIED2_IDS_EVENT_IPV6'
    snort_events_by_type[99] = 'UNIFIED2_IDS_EVENT_MPLS'
    snort_events_by_type[100] = 'UNIFIED2_IDS_EVENT_IPV6_MPLS'
    snort_events_by_type[104] = 'UNIFIED2_IDS_EVENT_VLAN'
    snort_events_by_type[105] = 'UNIFIED2_IDS_EVENT_IPV6_VLAN'
    snort_events_by_type[110] = 'UNIFIED2_EXTRA_DATA'
    snort_events_by_type[207] = 'UNIFIED2_IDS_EVENT_NG'
    snort_events_by_type[208] = 'UNIFIED2_IDS_EVENT_IPV6_NG'

    def __init__(self, output):
        self.__output=output
        self.__plugin_id = "1001"
        self.__plugin_name ='plugin_%s' % self.__plugin_id
        self.__plugin_type = "detector"
        self.__plugin_exclude_sids =  ''
        self.__plugin_exclude_inventory_sources =  ''
        self.__plugin_tzone =  ''
        self.__plugin_context =   ''
        #Detector.__init__(self, default_date_format=default_date_format, default_sensor=default_sensor, default_interface=default_interface, default_context=default_context, default_sensor_id=default_sensor_id, default_override_sensor=default_override_sensor, default_tzone=default_tzone, plugin_name=self.__plugin_name, plugin_id=self.__plugin_id, plugin_type=self.__plugin_type, plugin_exclude_sids=self.__plugin_exclude_sids, plugin_exclude_inventory_sources=self.__plugin_exclude_inventory_sources, plugin_context=self.__plugin_context, plugin_tzone=self.__plugin_tzone, event_consolidation_configuration=event_consolidation_configuration, output_queue=output_queue, stats_queue=stats_queue)
        self.stop_processing = multiprocessing.Event()
        self.__currentOpenedLogFile_fd = None
        self.__currentOpenedLogFile_name = ''
        self.__currentOpenedLogFile_size = 0
        self.__timestamp = 0
        self.__logfiles = []
        self.__skipOldEvents = True
        self.__state = None
        self.__interface =  ''
        self.__plugin_link_layer = 'ethernet'
        self.__plugin_unified_version = '2'
        self.__plugin_file_prefix = "unified2.alert"
        self.__plugin_directory = "/var/log/suricata/"
        
        #self.__plugin_state_shm = plugin_state_shm
        """
           #
        """

    def set_state(self, state):
        self.__state = state

    def stop(self, sig, params):
        self.stop_processing.set()
        self.__logfiles = []
        self.__skipOldEvents = False

    def __lookForFiles(self, updatemode = False):
        filter_str = '%s%s*' % (self.__plugin_directory, self.__plugin_file_prefix)
        tmpfiles = glob.glob(filter_str)
        snortfiles = []
        pattern = re.compile('(.*\\d{10})')
        for f in tmpfiles:
            if pattern.match(f):
                snortfiles.append(f)

        snortfiles.sort(reverse=True)
        if len(snortfiles) > 0:
            if not updatemode:
                self.__timestamp = 0
            last_one = snortfiles[0]
            last_timestamp = last_one[last_one.rindex('.') + 1:]
            if not updatemode:
                self.__timestamp = last_timestamp
                self.__logfiles.append(last_one)
            elif last_timestamp > self.__timestamp and last_one not in self.__logfiles:
                self.__logfiles.append(last_one)

    def __tryRotate(self):
        self.__lookForFiles(True)
        if len(self.__logfiles) > 0:
            self.__currentOpenedLogFile_fd.close()
            self.__currentOpenedLogFile_name = ''
            self.__currentOpenedLogFile_fd = None

    def __do_skipOldEvents(self):
        skipping_complete = False
        while not skipping_complete:
            pos = self.__currentOpenedLogFile_fd.tell()
            if pos + SNORT_FILE_HEADER_SIZE <= self.__currentOpenedLogFile_size:
                data = self.__currentOpenedLogFile_fd.read(SNORT_FILE_HEADER_SIZE)
                if len(data) != SNORT_FILE_HEADER_SIZE:
                    raise Exception, 'I/O error on file %s' % self.__currentOpenedLogFile_name
                type, size = struct.unpack('!II', data)
                if pos + size <= self.__currentOpenedLogFile_size:
                    self.__currentOpenedLogFile_fd.seek(size, os.SEEK_CUR)
                else:
                    skipping_complete = True
                    self.__currentOpenedLogFile_fd.seek(pos, os.SEEK_SET)
            else:
                skipping_complete = True
                self.__currentOpenedLogFile_fd.seek(pos, os.SEEK_SET)

        info('Skipped all existing events...')
    

    

    def process(self):
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, self.stop)
        if self.__plugin_link_layer != 'ethernet':
            info("This kind of snort parser only works for 'ethernet' linklayer.Please use the old one")
            return
        if int(self.__plugin_unified_version) != 2:
            info("This kind of snort parser only works for 'UNIFIED 2' V,ersion.Please use the old one")
            return
        if self.__plugin_file_prefix == '':
            info('Invalid prefix used.')
            return
        self.__lookForFiles()
        SnortUnpack.startPurgeEventsThread()
        last_valid_position = 0
        last_valid_packet_size = 0
        while not self.stop_processing.set():
            try:
                """
                if not self.__plugin_state_shm.enabled:
                    while not self.__plugin_state_shm.enabled:
                        sleep(1)
                """

                sleep(0.02)
                if self.__currentOpenedLogFile_fd is None:
                    if len(self.__logfiles) == 0:
                        self.__lookForFiles(True)
                        sleep(10)
                        continue
                    else:
                        self.__currentOpenedLogFile_name = self.__logfiles[0]
                        del self.__logfiles[0]
                        self.__timestamp = self.__currentOpenedLogFile_name[self.__currentOpenedLogFile_name.rindex('.') + 1:]
                        try:
                            self.__currentOpenedLogFile_fd = open(self.__currentOpenedLogFile_name, 'r')
                        except IOError:
                            error('Error reading file %s: it no longer exists' % self.__currentOpenedLogFile_name)

                else:
                    filestat = os.fstat(self.__currentOpenedLogFile_fd.fileno())
                    self.__currentOpenedLogFile_size = filestat[stat.ST_SIZE]
                    position = self.__currentOpenedLogFile_fd.tell()
                    if not self.__skipOldEvents:
                        debug('Skip evetns enabled!!')
                        self.__do_skipOldEvents()
                        self.__skipOldEvents = False
                    position = self.__currentOpenedLogFile_fd.tell()
                    if position + SNORT_FILE_HEADER_SIZE <= self.__currentOpenedLogFile_size:
                        data = self.__currentOpenedLogFile_fd.read(SNORT_FILE_HEADER_SIZE)
                        type, size = struct.unpack('!II', data)
                        info("type=%d  size=%d" %(type, size))
                    else:
                        self.__tryRotate()
                        continue
                    position = self.__currentOpenedLogFile_fd.tell()
                    max_tries = 10
                    while position + size > self.__currentOpenedLogFile_size and max_tries > 0:
                        info('waiting until Snort writes the packet data')
                        filestat = os.fstat(self.__currentOpenedLogFile_fd.fileno())
                        self.__currentOpenedLogFile_size = filestat[stat.ST_SIZE]
                        max_tries = max_tries - 1
                        sleep(0.1)

                    if position + size <= self.__currentOpenedLogFile_size:
                        data = self.__currentOpenedLogFile_fd.read(size)
                        position = self.__currentOpenedLogFile_fd.tell()
                        if self.snort_events_by_type.has_key(type):
                            last_valid_position = position - size - SNORT_FILE_HEADER_SIZE
                            last_valid_packet_size = size
                            if type == UNIFIED2_EVENT:
                                SnortUnpack.get_UNIFIED2_EVENT(data)
                            elif type == UNIFIED2_PACKET:
                                ev = SnortUnpack.get_Serial_Unified2Packet(data, type, size)
                                if ev:
                                    if self.__interface != '':
                                        ev['interface'] = self.__interface
                                    """
                                    send evnet
                                    self.send_message(ev)
                                    """
                                    self.__output.event(ev)
                                    print ev.to_sql()
                                    print str(ev)
                                  #
                            elif type == EVENT_TYPE_EXTRA_DATA:
                                SnortUnpack.get_EVENT_TYPE_EXTRA_DATA(data)
                            elif type == UNIFIED2_IDS_EVENT:
                                SnortUnpack.get_Serial_Unified2IDSEvent_legacy(data, type, size)
                            elif type == UNIFIED2_IDS_EVENT_IPV6:
                                SnortUnpack.get_Serial_Unified2IDSEventIPv6_legacy(data)
                            elif type == UNIFIED2_IDS_EVENT_MPLS:
                                SnortUnpack.get_UNIFIED2_IDS_EVENT_MPLS(data)
                            elif type == UNIFIED2_IDS_EVENT_IPV6_MPLS:
                                SnortUnpack.get_UNIFIED2_IDS_EVENT_IPV6_MPLS(data)
                            elif type == UNIFIED2_IDS_EVENT_VLAN:
                                SnortUnpack.get_Unified2IDSEvent(data)
                            elif type == UNIFIED2_IDS_EVENT_IPV6_VLAN:
                                SnortUnpack.get_Unified2IDSEventIPv6(data)
                            elif type == UNIFIED2_EXTRA_DATA:
                                SnortUnpack.get_SerialUnified2ExtraData(data)
                            elif type == UNIFIED2_IDS_EVENT_NG:
                                SnortUnpack.get_Unified2IDSEventNG(data)
                            elif type == UNIFIED2_IDS_EVENT_IPV6_NG:
                                SnortUnpack.get_Unified2IDSEventIPv6_NG(data)
                        else:
                            error('Unknown record type: %s, last valid cursor: %s, last valid packet size: %s, current_cursor: %s, theoric packet size: %s ' % (type,
                             last_valid_position,
                             last_valid_packet_size,
                             position,
                             size))
                            self.__currentOpenedLogFile_fd.seek(position, os.SEEK_CUR)
                    else:
                        self.__currentOpenedLogFile_fd.seek(position, os.SEEK_SET)
                        self.__tryRotate()
            except Exception as e:
                error('Something wrong has happened: %s' % str(e))

        SnortUnpack.stopPurgeEventsThread()


    
    
                 