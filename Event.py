from time import mktime, strptime, time,strftime
import time
from base64 import b64encode, b64decode
from bson.binary import BINARY_SUBTYPE, UUID_SUBTYPE, STANDARD, Binary
from uuid import UUID, uuid1

from bson import BSON
from syslog_log import *

class Command(object):

    def __init__(self):
        pass

    def to_string(self):
        pass

    def to_bson(self):
        pass

    def is_idm_event(self):
        return False
    
class Event(Command):
    EVENT_BSON = {'type': 'str',
     'date': 'int64',
     'sensor': 'str',
     'device': 'str',
     'interface': 'str',
     'plugin_id': 'int32',
     'plugin_sid': 'int32',
     'priority': 'int32',
     'protocol': 'str',
     'src_ip': 'str',
     'dst_ip': 'str',
     'src_port': 'int32',
     'dst_port': 'int32',
     'username': 'str',
     'password': 'str',
     'filename': 'str',
     'userdata1': 'str',
     'userdata2': 'str',
     'userdata3': 'str',
     'userdata4': 'str',
     'userdata5': 'str',
     'userdata6': 'str',
     'userdata7': 'str',
     'userdata8': 'str',
     'userdata9': 'str',
     'occurrences': 'int32',
     'log': 'binary',
     'snort_sid': 'int32',
     'snort_cid': 'int32',
     'fdate': 'str',
     'tzone': 'double',
     'ctx': 'uuid',
     'sensor_id': 'uuid',
     'event_id': 'uuid',
     'binary_data': 'str',
     'domain': 'str',
     'mail': 'str',
     'os': 'str',
     'cpu': 'str',
     'video': 'str',
     'service': 'str',
     'software': 'str',
     'ip': 'str',
     'mac': 'str',
     'inventory_source': 'int32',
     'login': 'bool',
     'pulses': 'object'}
    EVENT_BASE64 = ['username',
     'password',
     'filename',
     'userdata1',
     'userdata2',
     'userdata3',
     'userdata4',
     'userdata5',
     'userdata6',
     'userdata7',
     'userdata8',
     'userdata9',
     'log',
     'domain',
     'mail',
     'os',
     'cpu',
     'video',
     'service',
     'software']
    EVENT_TYPE = 'event'
    EVENT_ATTRS = ['type',
     'date',
     'sensor',
     'device',
     'interface',
     'plugin_id',
     'plugin_sid',
     'priority',
     'protocol',
     'src_ip',
     'src_port',
     'dst_ip',
     'dst_port',
     'username',
     'password',
     'filename',
     'userdata1',
     'userdata2',
     'userdata3',
     'userdata4',
     'userdata5',
     'userdata6',
     'userdata7',
     'userdata8',
     'userdata9',
     'occurrences',
     'log',
     'snort_sid',
     'snort_cid',
     'fdate',
     'tzone',
     'ctx',
     'sensor_id',
     'event_id',
     'binary_data',
     'pulses']

    def __init__(self):
        self.event = {}
        self.event['event_type'] = self.EVENT_TYPE
        self.normalized = False
        self.is_idm = self.EVENT_TYPE == 'idm-event'

    def __setitem__(self, key, value):
        if key in ('sensor', 'device') and self.is_idm:
            return
        if key in ('pid', 'cpe', 'device_id'):
            return
        if isinstance(value, basestring) and key not in self.EVENT_BASE64:
            value = value.rstrip('\n')
        if key == 'sensor':
            if 'device' in self.event:
                device_data = self.event['device']
                if device_data != '':
                    return
            key = 'device'
        if key in self.EVENT_ATTRS:
            self.event[key] = value
            if key == 'date' and not self.normalized:
                date_epoch = int(time())
                try:
                    date_epoch = int(mktime(strptime(value, '%Y-%m-%d %H:%M:%S')))
                    self.event['fdate'] = value
                    self.event['date'] = date_epoch
                    self.normalized = True
                except ValueError:
                    error('There was an error parsing a string date (%s)' % value)

        elif key != 'event_type' and not isinstance(self, EventIdm):
            error('Bad event attribute: %s' % key)

    def __getitem__(self, key):
        return self.event.get(key, None)

    def __repr__(self):
        return self.to_string()

    def to_string(self):
        event = self.__class__.EVENT_TYPE.encode('utf-8')
        for attr in self.EVENT_ATTRS:
            if self[attr]:
                value = self.event[attr]
                if attr in self.EVENT_BASE64:
                    value = b64encode(value)
                event += ' %s="%s"' % (attr, value)

        if not self.is_idm:
            event += ' event_id="%s"' % Event.__get_uuid()
        return event + '\n'

    def dict(self):
        return self.event

    def sanitize_value(self, string):
        return str(string).strip().replace('"', '\\"').replace("'", '')

    def is_idm_event(self):
        return self.is_idm

    def to_bson(self):
        event_data = {}
        for attr, t in self.EVENT_BSON.items():
            if self[attr]:
                data = self[attr]
                if t == 'str':
                    event_data[attr] = str(data)
                elif t == 'uuid':
                    event_data[attr] = UUID(data)
                elif t == 'int32':
                    event_data[attr] = int(data)
                elif t == 'int64':
                    event_data[attr] = long(data)
                elif t == 'binary':
                    event_data[attr] = Binary(bytes(data))
                elif t == 'double':
                    event_data[attr] = float(data)
                elif t == 'bool':
                    event_data[attr] = data.lower() in ('yes', 'y', 'true', 't', '1')
                elif t == 'object':
                    event_data[attr] = data

        if not self.is_idm:
            event_data['event_id'] = Event.__get_uuid()
        return BSON.encode({self.EVENT_TYPE: event_data})
    
    def to_sql(self):
            event_attr =["event_id","plugin_id","plugin_sid","protocol","src_ip","src_port","dst_ip","dst_port","date","log","binary_data"] 
            self.event['event_id'] = Event.__get_uuid()
            self.event['date'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
             
            query = 'INSERT INTO event ('
            for attr in event_attr:
                query += '%s,' % attr

            query = query.rstrip(',')
            query += ') VALUES ('
            
            for attr in event_attr:
                value = ''
                if self.event[attr] is not None:
                    if attr=="log":
                      value = b64encode( self.event[attr])
                    else :
                      value = self.event[attr]
                    print self.event[attr]
                else :
                    value=""
                    
                query += "'%s'," % value
                
            query = query.rstrip(',')
            query += ');'
            #debug(query)
            
            return  query
        
        
    def get(self, key, default_value):
        return self.event.get(key, default_value)

    @staticmethod
    def __get_uuid():
        ev_uuid = uuid1()
        return UUID(int=((ev_uuid.int & 79228162514264337593543950335L) << 32) + ev_uuid.time_low)


class WatchRule(Event):
    EVENT_TYPE = 'event'
    EVENT_BASE64 = ['username',
     'password',
     'filename',
     'userdata1',
     'userdata2',
     'userdata3',
     'userdata4',
     'userdata5',
     'userdata6',
     'userdata7',
     'userdata8',
     'userdata9',
     'log',
     'domain',
     'mail',
     'os',
     'service']
    EVENT_ATTRS = ['type',
     'date',
     'fdate',
     'tzone',
     'sensor',
     'device',
     'interface',
     'src_ip',
     'dst_ip',
     'protocol',
     'plugin_id',
     'plugin_sid',
     'condition',
     'value',
     'port_from',
     'src_port',
     'port_to',
     'dst_port',
     'interval',
     'from',
     'to',
     'absolute',
     'log',
     'userdata1',
     'userdata2',
     'userdata3',
     'userdata4',
     'userdata5',
     'userdata6',
     'userdata7',
     'userdata8',
     'userdata9',
     'filename',
     'username',
     'ctx',
     'sensor_id',
     'event_id']


class HostInfoEvent(Event):
    EVENT_TYPE = 'idm-event'
    EVENT_BSON = {'device': 'str',
     'username': 'str',
     'password': 'str',
     'filename': 'str',
     'userdata1': 'str',
     'userdata2': 'str',
     'userdata3': 'str',
     'userdata4': 'str',
     'userdata5': 'str',
     'userdata6': 'str',
     'userdata7': 'str',
     'userdata8': 'str',
     'userdata9': 'str',
     'ctx': 'uuid',
     'domain': 'str',
     'mail': 'str',
     'organization': 'str',
     'service': 'str',
     'software': 'str',
     'hostname': 'str',
     'os': 'str',
     'cpu': 'str',
     'memory': 'int32',
     'video': 'str',
     'state': 'str',
     'ip': 'str',
     'mac': 'str',
     'login': 'bool',
     'reliability': 'str',
     'inventory_source': 'int32'}
    EVENT_ATTRS = ['device',
     'username',
     'password',
     'filename',
     'userdata1',
     'userdata2',
     'userdata3',
     'userdata4',
     'userdata5',
     'userdata6',
     'userdata7',
     'userdata8',
     'userdata9',
     'ctx',
     'domain',
     'mail',
     'organization',
     'service',
     'software',
     'hostname',
     'os',
     'cpu',
     'memory',
     'video',
     'state',
     'ip',
     'mac',
     'login',
     'reliability',
     'inventory_source']

    def __init__(self):
        super(HostInfoEvent, self).__init__()


class EventIdm(HostInfoEvent):

    def __init__(self):
        super(EventIdm, self).__init__()
