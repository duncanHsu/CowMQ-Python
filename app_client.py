from flask import Flask
import json

from cow_mq.client import Client as CowMQClient
import threading
import logging

SERVER_DOMAIN = 'www.hcy.com'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cow_mq_2017'
app.config['cow_mq_ip'] = '192.168.159.114'
#app.config['cow_mq_ip'] = 'your_mqtt_ip'
app.config['cow_mq_port'] = 1883
app.config['cow_mq_username'] = None
app.config['cow_mq_password'] = None
app.config['cow_mq_tls_ca_certs'] = None
app.config['cow_mq_tls_certfile'] = None
app.config['cow_mq_tls_keyfile'] = None

cow_client = CowMQClient(app, logging_level=logging.DEBUG)
cow_client.register_server_connected(SERVER_DOMAIN)


def sign_in_callback(domain, rule, rsp_data):
    print('sign_in async rsp: {}'.format(rsp_data))


def thread_send():
    data = json.dumps({'type': 1})
    print('version sync send: {}'.format(data))
    rsp_data = cow_client.sync_send(SERVER_DOMAIN, '/version',
                                    data.encode('utf-8'), timeout=10)
    print('version sync rsp: {}'.format(rsp_data))


def on_cow_mq_client_connect(self, client, userdata, flags, rc):
    data = json.dumps({'username': 'admin', 'password': '123456'})
    print('sign_in async send: {}'.format(data))
    cow_client.async_send(SERVER_DOMAIN, '/account/sign_in',
                          data.encode('utf-8'), sign_in_callback, timeout=10)

    t = threading.Thread(target=thread_send)
    t.start()


def on_cow_mq_server_connect(domain):
    print('on_cow_mq_server_connect: {}'.format(domain))


def on_cow_mq_server_disconnect(domain):
    print('on_cow_mq_server_disconnect: {}'.format(domain))


cow_client.on_connect = on_cow_mq_client_connect
cow_client.on_server_connect = on_cow_mq_server_connect
cow_client.on_server_disconnect = on_cow_mq_server_disconnect

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=21011)
