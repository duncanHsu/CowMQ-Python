import paho.mqtt.client as MQTT
from enum import Enum
from cow_mq.util import Util, DataType
from datetime import datetime
import time
import copy
import logging
import json
import threading


class SendType(Enum):
    NONE = 0
    SYNC = 1
    ASYNC = 2


class ResponseStatus(Enum):
    NONE = 0
    SUCCESS = 1
    TIMEOUT = 2


class ResponseData:
    status = ResponseStatus.NONE
    data_bytes = None

    def __repr__(self):
        return '<ResponseData status:{}, data_bytes:{}>'.format(
            self.status, self.data_bytes)


class Client:

    class SendData:
        domain = None
        rule = None
        completed = False
        send_type = SendType.NONE
        rsp_data = None
        rsp_callback = None
        timeout_timer = None

        def __init__(self, domain, rule, completed=False,
                     send_type=SendType.NONE,
                     rsp_data=ResponseData(), rsp_callback=None,
                     timeout_timer=None):
            self.domain = domain
            self.rule = rule
            self.completed = completed
            self.send_type = send_type
            self.rsp_data = rsp_data
            self.rsp_callback = rsp_callback
            self.timeout_timer = timeout_timer

    mqtt_client = None
    mqtt_ip = None
    mqtt_port = None
    mqtt_username = None
    mqtt_password = None
    mqtt_tls_ca_certs = None
    mqtt_tls_certfile = None
    mqtt_tls_keyfile = None

    on_connect = None
    on_disconnect = None
    on_subscribe = None
    on_message = None

    on_server_connect = None
    on_server_disconnect = None

    topic_domain_rule_dic = {}
    registered_server_data = []

    def __init__(self, config, logging_level=logging.WARNING):
        self.logger = logging.getLogger('CowMQ Client')
        self.logger.setLevel(logging_level)
        ch = logging.StreamHandler()
        ch.setLevel(logging_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        mqtt_ip = Util.get_cow_mq_ip_from_config(config)
        mqtt_port = Util.get_cow_mq_port_from_config(config)
        mqtt_username = Util.get_cow_mq_username_from_config(config)
        mqtt_password = Util.get_cow_mq_password_from_config(config)
        mqtt_tls_ca_certs = Util.get_cow_mq_tls_ca_certs_from_config(
            config)
        mqtt_tls_certfile = Util.get_cow_mq_tls_certfile_from_config(
            config)
        mqtt_tls_keyfile = Util.get_cow_mq_tls_keyfile_from_config(
            config)

        self.mqtt_ip = mqtt_ip
        self.mqtt_port = mqtt_port
        self.mqtt_username = mqtt_username
        self.mqtt_password = mqtt_password

        # self.mqtt_client = MQTT.Client(transport='websockets')
        self.mqtt_client = MQTT.Client()
        self.mqtt_client.on_connect = self.on_connect_mqtt
        self.mqtt_client.on_disconnect = self.on_disconnect_mqtt
        self.mqtt_client.on_subscribe = self.on_subscribe_mqtt
        self.mqtt_client.on_message = self.on_message_mqtt

        if (mqtt_username is not None and mqtt_password is not None):
            self.mqtt_client.username_pw_set(
                self.mqtt_username, self.mqtt_password)

        if mqtt_tls_ca_certs is not None:
            self.mqtt_client.tls_set(mqtt_tls_ca_certs, mqtt_tls_certfile,
                                     mqtt_tls_keyfile)

        self.mqtt_client.connect(self.mqtt_ip, self.mqtt_port)
        self.mqtt_client.loop_start()

    def on_connect_mqtt(self, client, userdata, flags, rc):
        self.logger.debug("connect rc:{}".format(rc))

        if self.on_connect:
            self.on_connect(self, client, userdata, flags, rc)

    def on_disconnect_mqtt(self, client, userdata, rc):
        self.logger.debug("disconnect rc:{}".format(rc))

        self.mqtt_client.loop_stop()

        if self.on_disconnect:
            self.on_disconnect(self, client, userdata, rc)

    def on_subscribe_mqtt(self, client, userdata, mid, granted_qos):
        # self.logger.debug("subscribe mid:{}, granted_qos:{}".format(
        #     mid, granted_qos))

        if self.on_subscribe:
            self.on_subscribe(self, client, userdata, mid, granted_qos)

    def on_message_mqtt(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload

        data_type, data_bytes, rsp_topic = Util.decode(payload)
        if data_type == DataType.NONE:
            self.logger.debug("on_message topic:{}, payload:{}".format(
                topic, payload))
            if self.on_message:
                self.on_message(self, client, userdata, msg)
            return

        if data_type == DataType.INFO:
            if Util.is_connected_topic(topic):
                domain = Util.get_domain_from_connected_topic(topic)
                data_str = data_bytes.decode('utf-8')
                data = json.loads(data_str)
                connected = data['connected']
                if connected:
                    self.logger.debug('server({}) connected'.format(domain))
                    if self.on_server_connect:
                        self.on_server_connect(domain)
                else:
                    self.logger.debug('server({}) disconnected'.format(domain))
                    if self.on_server_disconnect:
                        self.on_server_disconnect(domain)
            return

        if topic not in self.topic_domain_rule_dic:
            return

        send_data = self.topic_domain_rule_dic[topic]
        send_data.rsp_data.status = ResponseStatus.SUCCESS
        send_data.rsp_data.data_bytes = data_bytes
        send_data.completed = True
        # self.logger.debug('''message:
        #                         domain:{},
        #                         rule:{},
        #                         data_type:{},
        #                         rsp_topic:{},
        #                         data_bytes:{}
        #                   '''.format(send_data.domain, send_data.rule,
        #                              data_type, rsp_topic,
        #                              send_data.rsp_data))

        if send_data.send_type == SendType.ASYNC:
            send_data.timeout_timer.cancel()
            del self.topic_domain_rule_dic[topic]
            self.logger.debug(
                'async_send receive domain:{}, rule:{}, payload:{}'.
                format(send_data.domain, send_data.rule,
                       send_data.rsp_data))
            if send_data.rsp_callback:
                send_data.rsp_callback(
                    send_data.domain, send_data.rule, send_data.rsp_data)

    def subscribe(self, topic, qos=0):
        self.mqtt_client.subscribe(topic, qos)

    def unsubscribe(self, topic):
        self.mqtt_client.unsubscribe(topic)

    def publish(self, topic, payload=None, qos=0, retain=False):
        self.mqtt_client.publish(topic, payload, qos, retain)

    def register_server_connected(self, domain):
        if not Util.can_use_domain(domain):
            self.logger.error('domain is wrong format: {}'.format(domain))
            raise Exception('Server domain is wrong format')

        connected_topic = Util.generate_connected_topic(domain)
        self.mqtt_client.subscribe(connected_topic, qos=1)
        self.registered_server_data.append(domain)
        return True

    def unregister_server_connected(self, domain):
        if not Util.can_use_domain(domain):
            self.logger.error('domain is wrong format: {}'.format(domain))
            raise Exception('Server domain is wrong format')

        connected_topic = Util.generate_connected_topic(domain)
        self.mqtt_client.unsubscribe(connected_topic, qos=1)
        self.registered_server_data.remove(domain)
        return True

    def registered_server_connected_list(self):
        return copy.deepcopy(self.registered_server_data)

    def sync_send(self, domain, rule, payload, timeout=30):
        if not Util.can_use_domain(domain):
            self.logger.error('domain({}) is wrong format'.format(domain))
            raise Exception('Server domain is wrong format')

        if rule is not None and not Util.can_use_rule(rule):
            self.logger.error('Rule({}) can not be use'.format(rule))
            raise Exception(
                'Rule({}) can not be use'.format(rule))

        topic = Util.generate_request_topic(domain, rule)
        rsp_topic = Util.generate_response_topic(domain)
        data_bytes = Util.encode(DataType.REQ, payload, rsp_topic)

        self.topic_domain_rule_dic[rsp_topic] = Client.SendData(
            domain, rule, send_type=SendType.SYNC)

        self.mqtt_client.subscribe(rsp_topic, qos=1)
        self.mqtt_client.publish(topic, payload=data_bytes, qos=1)
        self.logger.debug('sync_send topic:{}, payload:{}'.format(
            topic, payload))

        start_time = datetime.now()
        while True:
            send_data = self.topic_domain_rule_dic[rsp_topic]
            delta = datetime.now() - start_time
            if delta.total_seconds() > timeout:
                send_data.rsp_data.status = ResponseStatus.TIMEOUT
                send_data.completed = True
                break
            if send_data.completed:
                break
            time.sleep(0.01)

        del self.topic_domain_rule_dic[rsp_topic]

        self.logger.debug('sync_send receive topic:{}, payload:{}'.format(
            topic, send_data.rsp_data))
        return send_data.rsp_data

    def async_send(self, domain, rule, payload, callback, timeout=30):
        if not Util.can_use_domain(domain):
            self.logger.error('domain({}) is wrong format'.format(domain))
            raise Exception('Server domain is wrong format')

        if rule is not None and not Util.can_use_rule(rule):
            self.logger.error('Rule({}) can not be use'.format(rule))
            raise Exception(
                'Rule({}) can not be use'.format(rule))

        topic = Util.generate_request_topic(domain, rule)
        rsp_topic = Util.generate_response_topic(domain)
        data_bytes = Util.encode(DataType.REQ, payload, rsp_topic)

        self.topic_domain_rule_dic[rsp_topic] = Client.SendData(
            domain, rule, send_type=SendType.ASYNC, rsp_callback=callback)
        self.mqtt_client.subscribe(rsp_topic, qos=1)
        self.mqtt_client.publish(topic, payload=data_bytes, qos=1)
        self.logger.debug('async_send topic:{}, payload:{}'.format(
            topic, payload))

        send_data = self.topic_domain_rule_dic[rsp_topic]
        t = threading.Timer(timeout, self.async_timeout,
                            [rsp_topic, send_data])
        send_data.timeout_timer = t
        t.start()

        return True

    def async_timeout(self, rsp_topic, send_data):
        if send_data.completed:
            return

        send_data.completed = True
        send_data.rsp_data.status = ResponseStatus.TIMEOUT

        del self.topic_domain_rule_dic[rsp_topic]
        self.logger.debug('async_send receive domain:{}, rule:{}, payload:{}'.
                          format(send_data.domain, send_data.rule,
                                 send_data.rsp_data))
        if send_data.rsp_callback:
            send_data.rsp_callback(
                send_data.domain, send_data.rule, send_data.rsp_data)
