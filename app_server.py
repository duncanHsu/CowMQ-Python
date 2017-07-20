from flask import Flask
import json

from cow_mq.server import Server as CowMQServer
from views.api_account import api_account_bp

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

cow_server = CowMQServer(app, SERVER_DOMAIN, logging_level=logging.DEBUG)
cow_server.register_blueprint(api_account_bp, url_prefix='/account')


@cow_server.route('/version')
def test(payload):
    data = json.dumps({'version': '0.0.1'})
    return data.encode('utf-8')


if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=11011)
