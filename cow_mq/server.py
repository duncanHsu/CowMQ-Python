import paho.mqtt.client as MQTT
import json
import logging

from cow_mq.util import Util, DataType
from cow_mq.blueprint import Blueprint as CowMQBlueprint
from cow_mq.blueprint import BlueprintRouteState


class Server:

    logger = None
    domain = None

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

    rule_fun_dic = None
    root_blueprint = None

    def __init__(self, config, domain, logging_level=logging.WARNING):
        self.logger = logging.getLogger('CowMQ Server({})'.format(domain))
        self.logger.setLevel(logging_level)
        ch = logging.StreamHandler()
        ch.setLevel(logging_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if not Util.can_use_domain(domain):
            self.logger.error('domain is wrong format: {}'.format(domain))
            raise Exception('Server domain is wrong format')

        self.domain = domain

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

        cow_mq_topic = Util.generate_connected_topic(self.domain)
        data = json.dumps({'connected': False})
        data_bytes = Util.encode(DataType.INFO, data.encode('utf-8'))
        self.mqtt_client.will_set(cow_mq_topic, payload=data_bytes, qos=1)

        self.mqtt_client.connect(self.mqtt_ip, self.mqtt_port)
        self.mqtt_client.loop_start()
        # self.mqtt_client.loop_forever

        self.rule_fun_dic = {}
        self.root_blueprint = CowMQBlueprint('cow_md_root', __name__)

        self.register_blueprint(self.root_blueprint)

    def on_connect_mqtt(self, client, userdata, flags, rc):
        self.logger.debug("connect rc:{}".format(rc))

        topic = Util.generate_request_topic(self.domain, '/#')
        self.mqtt_client.subscribe(topic, qos=1)

        cow_mq_topic = Util.generate_connected_topic(self.domain)
        data = json.dumps({'connected': True})
        data_bytes = Util.encode(DataType.INFO, data.encode('utf-8'))
        self.mqtt_client.publish(cow_mq_topic, payload=data_bytes, qos=1)

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

        if not Util.is_request_topic(self.domain, topic):
            self.logger.debug("on_message topic:{}, payload:{}".format(
                topic, payload))
            if self.on_message:
                self.on_message(self, client, userdata, msg)
            return

        req_topic = Util.get_topic_from_request_topic(self.domain, topic)
        self.logger.debug('''message:
                                topic:{},
                                data_type:{},
                                rsp_topic:{},
                                data_bytes:{}
                          '''.format(req_topic, data_type, rsp_topic,
                                     data_bytes))

        if req_topic in self.rule_fun_dic:
            func = self.rule_fun_dic[req_topic]
            result_data = func(data_bytes)

            if result_data is None:
                result_data = bytes()

            data_bytes = Util.encode(DataType.RSP, result_data)
            self.mqtt_client.publish(rsp_topic, payload=data_bytes, qos=1)

    def register_blueprint(self, blueprint, url_prefix=None):
        blueprint.route_change_callback(self.blueprint_route_change)
        if url_prefix is not None and not Util.can_use_rule(url_prefix):
            self.logger.error('register_blueprint url_prefix({})\
                can not be use'.format(url_prefix))
            raise Exception(
                'register_blueprint url_prefix({}) can not be use'.format(
                    url_prefix))

        for rule, func in blueprint.rule_fun_dic.items():
            r = None
            if url_prefix is None:
                r = rule
            else:
                r = url_prefix + rule

            self.rule_fun_dic[r] = func
        self.logger.debug('rule func data: {}'.format(self.rule_fun_dic))
        return True

    def blueprint_route_change(self, state, rule, f):
        self.logger.debug('blueprint change route:{},\
         func:{}, state:{}'.format(rule, f, state))
        if (state == BlueprintRouteState.ADD):
            self.rule_fun_dic[rule] = f
        elif (state == BlueprintRouteState.DEL):
            del self.rule_fun_dic[rule]
        elif (state == BlueprintRouteState.CLEAR):
            self.rule_fun_dic = {}
        self.logger.debug('rule func data: {}'.format(self.rule_fun_dic))

    def subscribe(self, topic, qos=0):
        self.mqtt_client.subscribe(topic, qos)

    def publish(self, topic, payload=None, qos=0, retain=False):
        self.mqtt_client.publish(topic, payload, qos, retain)

    def add_route(self, rule, f):
        return self.root_blueprint.add_route(rule, f)

    def remove_route(self, rule):
        return self.root_blueprint.remove_route(rule)

    def exist_route(self, rule):
        return self.root_blueprint.exist_route(rule)

    def clear_route(self):
        return self.root_blueprint.clear_route()

    def route_list(self):
        return self.root_blueprint.route_list()

    def route(self, rule):
        def decorator(f):
            if not self.add_route(rule, f):
                raise Exception('Server route rule({}) is exist'.format(rule))
            return f
        return decorator
