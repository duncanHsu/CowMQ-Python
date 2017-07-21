# CowMQ

[![CocoaPods](https://img.shields.io/cocoapods/l/AFNetworking.svg)]()
[![PyPI](https://img.shields.io/pypi/v/nine.svg)]()
[![PyPI](https://img.shields.io/badge/python-3.4%2C%203.5%2C%203.6-blue.svg)]()

The CowMQ is a simple client-server protocol over MQTT for Python


## Other Platforms
* [CowMQ-Nodejs](https://github.com/duncanHsu/CowMQ-Nodejs)
* [CowMQ-iOS](https://github.com/duncanHsu/CowMQ-iOS)
* [CowMQ-Android](https://github.com/duncanHsu/CowMQ-Android)

## Installation
> pip install CowMQ

## Quick Start
### Config
```
config = {}
config['cow_mq_ip'] = 'mqtt_borker_ip'
config['cow_mq_port'] = 'mqtt_broker_port
config['cow_mq_username'] = 'mqtt_username' # option
config['cow_mq_password'] = 'mqtt_password' # option
config['cow_mq_tls_ca_certs'] = None # option
config['cow_mq_tls_certfile'] = None # option
config['cow_mq_tls_keyfile'] = None # option
```

### Server
```
from cow_mq.server import Server as CowMQServer

cow_server = CowMQServer(config, 'server_domain')

@cow_server.route('/version')
def version(payload):
    data = json.dumps({'version': '0.0.1'})
    return data.encode('utf-8')
```

### Blueprint
```
from views.api_account import api_account_bp

cow_server.register_blueprint(api_account_bp, url_prefix='/account')
```

api_account.py

```
from cow_mq.blueprint import Blueprint as CowMQBlueprint

api_account_bp = CowMQBlueprint('api_account', __name__)

@api_account_bp.route("/sign_in")
def sign_in(payload):
    data = json.dumps({'token': 'abcde123456'})
    return data.encode('utf-8')
```

### Client
```
from cow_mq.client import Client as CowMQClient

cow_client = CowMQClient(config)

def version_callback(domain, rule, rsp_data):
    print('version async rsp: {}'.format(rsp_data))

data = json.dumps({'type': 1})
cow_client.async_send('server_domain', '/version', data.encode('utf-8'), version_callback)

```

### Listener Server Status
```
def on_cow_mq_server_connect(domain):
    print('on_cow_mq_server_connect: {}'.format(domain))

def on_cow_mq_server_disconnect(domain):
    print('on_cow_mq_server_disconnect: {}'.format(domain))
    
cow_client.register_server_connected('server_domain')
cow_client.on_server_connect = on_cow_mq_server_connect
cow_client.on_server_disconnect = on_cow_mq_server_disconnect
```

## Author

- Duncan Hsu <protosss2@gmail.com>

## License

CowMQ is available under the Apache License 2.0.
