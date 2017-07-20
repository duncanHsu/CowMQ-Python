from enum import Enum
import re
import uuid


class DataType(Enum):
    NONE = 0
    INFO = 1
    REQ = 2
    RSP = 3
    FILE = 4


class Util:
    COW_MQ_PREFIX = 'cow_mq'

    @staticmethod
    def encode(data_type, data_bytes, rsp_topic=None):
        if not isinstance(data_bytes, bytes):
            raise Exception('data_bytes is wrong type, need to be bytes.')

        if data_type == DataType.REQ and rsp_topic is None:
            raise Exception('rsp_topic is required.')

        data_type_int = int(data_type.value)

        data = bytes('hcy'.encode('utf-8'))
        data += data_type_int.to_bytes(1, byteorder='big')

        if rsp_topic is not None:
            rsp_topic_len = len(rsp_topic)
            data += rsp_topic_len.to_bytes(2, byteorder='big')
            data += rsp_topic.encode('utf-8')

        data += data_bytes
        return bytearray(data)

    @staticmethod
    def decode(data_bytes):
        if not isinstance(data_bytes, bytes):
            raise Exception('data_bytes is wrong type, need to be bytes.')

        id = data_bytes[0:3].decode("utf-8")
        if not id == 'hcy':
            return DataType.NONE, None, data_bytes

        try:
            data_type = DataType(data_bytes[3])
        except ValueError:
            return DataType.NONE, None, data_bytes

        rsp_topic = None
        index = 4
        if data_type == DataType.REQ:
            rsp_topic_len = int.from_bytes(
                data_bytes[index:6], byteorder='big')
            index = 6 + rsp_topic_len
            rsp_topic_bytes = data_bytes[6:index]
            rsp_topic = rsp_topic_bytes.decode("utf-8")
        data_bytes = data_bytes[index:]

        return data_type, data_bytes, rsp_topic

    @staticmethod
    def generate_server_topic(domain, rule):
        return '/{}/{}{}'.format(Util.COW_MQ_PREFIX, domain, rule)

    @staticmethod
    def generate_info_topic(domain, rule):
        return '/{}/{}/info{}'.format(Util.COW_MQ_PREFIX, domain, rule)

    @staticmethod
    def generate_request_topic(domain, rule):
        return '/{}/{}/req{}'.format(Util.COW_MQ_PREFIX, domain, rule)

    @staticmethod
    def generate_response_topic(domain):
        return '/{}/{}/rsp/{}'.format(Util.COW_MQ_PREFIX, domain, uuid.uuid4())

    @staticmethod
    def generate_connected_topic(domain):
        return '/{}/{}/info/connected'.format(Util.COW_MQ_PREFIX, domain)

    @staticmethod
    def is_server_topic(domain, topic):
        return topic.startswith('/{}/{}'.format(Util.COW_MQ_PREFIX, domain))

    @staticmethod
    def is_info_topic(domain, topic):
        return topic.startswith('/{}/{}/info'.format(
            Util.COW_MQ_PREFIX, domain))

    @staticmethod
    def is_request_topic(domain, topic):
        return topic.startswith('/{}/{}/req'.format(
            Util.COW_MQ_PREFIX, domain))

    @staticmethod
    def is_response_topic(domain, topic):
        return topic.startswith('/{}/{}/rsp'.format(
            Util.COW_MQ_PREFIX, domain))

    @staticmethod
    def is_connected_topic(topic):
        if not topic.startswith('/{}/'.format(Util.COW_MQ_PREFIX)):
            return False
        if not topic.endswith('/info/connected'):
            return False
        return True

    @staticmethod
    def get_topic_from_server_topic(domain, topic):
        if not Util.is_server_topic(domain, topic):
            return None
        return topic[len(Util.COW_MQ_PREFIX) + len(domain) + 2:]

    @staticmethod
    def get_topic_from_info_topic(domain, topic):
        if not Util.is_info_topic(domain, topic):
            return None
        return topic[len(Util.COW_MQ_PREFIX) + len(domain) + 4 + 3:]

    @staticmethod
    def get_topic_from_request_topic(domain, topic):
        if not Util.is_request_topic(domain, topic):
            return None
        return topic[len(Util.COW_MQ_PREFIX) + len(domain) + 3 + 3:]

    @staticmethod
    def get_domain_from_connected_topic(topic):
        if not Util.is_connected_topic(topic):
            return None
        index = topic.find('/info/connected')
        domain = topic[len(Util.COW_MQ_PREFIX) + 2:index]
        return domain

    @staticmethod
    def get_cow_mq_ip_from_config(config):
        mqtt_ip = None
        if 'cow_mq_ip' in config:
            mqtt_ip = config['cow_mq_ip']
        if mqtt_ip is None:
            raise Exception('cow_mq_ip is None')
        if not Util.is_ip_address(mqtt_ip):
            raise Exception(
                'cow_mq_ip is wrong format, need to be ip address string.')
        return mqtt_ip

    @staticmethod
    def get_cow_mq_port_from_config(config):
        mqtt_port = 1883
        if 'cow_mq_port' in config:
            tmp_mqtt_port = config['cow_mq_port']
            if tmp_mqtt_port is not None:
                mqtt_port = tmp_mqtt_port

            if not isinstance(mqtt_port, int):
                raise Exception(
                    'cow_mq_port is wrong format, need to be int.')
        return mqtt_port

    @staticmethod
    def get_cow_mq_username_from_config(config):
        mqtt_username = None
        if 'cow_mq_username' in config:
            mqtt_username = config['cow_mq_username']

            if mqtt_username is not None and\
               not isinstance(mqtt_username, int):
                raise Exception(
                    'cow_mq_username is wrong format, need to be string.')
        return mqtt_username

    @staticmethod
    def get_cow_mq_password_from_config(config):
        mqtt_password = None
        if 'cow_mq_password' in config:
            mqtt_password = config['cow_mq_password']

            if mqtt_password is not None and\
               not isinstance(mqtt_password, str):
                raise Exception(
                    'cow_mq_password is wrong format, need to be string.')
        return mqtt_password

    @staticmethod
    def get_cow_mq_tls_ca_certs_from_config(config):
        tls_ca_certs = None
        if 'cow_mq_tls_ca_certs' in config:
            tls_ca_certs = config['cow_mq_tls_ca_certs']

            if tls_ca_certs is not None and\
               not isinstance(tls_ca_certs, str):
                raise Exception(
                    'cow_mq_tls_ca_certs is wrong format, need to be string.')
        return tls_ca_certs

    @staticmethod
    def get_cow_mq_tls_certfile_from_config(config):
        tls_certfile = None
        if 'cow_mq_tls_certfile' in config:
            tls_certfile = config['cow_mq_tls_certfile']
        return tls_certfile

    @staticmethod
    def get_cow_mq_tls_keyfile_from_config(config):
        tls_keyfile = None
        if 'cow_mq_tls_keyfile' in config:
            tls_keyfile = config['cow_mq_tls_keyfile']
        return tls_keyfile

    @staticmethod
    def can_use_rule(rule):
        result = re.match(r'(/[^/][a-zA-Z0-9\_]*[\<\>]?)+\Z', rule)
        if result is None:
            return False
        return True

    @staticmethod
    def can_use_domain(domain):
        result = re.match(r'^(([A-Za-z0-9\_]+)\.?)+[A-Za-z0-9\_]+$', domain)
        if result is None:
            return False
        return True

    @staticmethod
    def is_ip_address(ip_str):
        result = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_str)
        if result is None:
            return False
        return True
