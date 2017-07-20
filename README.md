# CowMQ
The CowMQ is a simple client-server protocol over MQTT for Python


## Other platforms
* [CowMQ-Nodejs](https://github.com/duncanHsu/CowMQ-Nodejs)
* [CowMQ-iOS](https://github.com/duncanHsu/CowMQ-iOS)
* [CowMQ-Android](https://github.com/duncanHsu/CowMQ-Android)

## How to install
> pip install CowMQ

## How to use
### Config
```
app.config['cow_mq_ip'] = 'mqtt_borker_ip'
app.config['cow_mq_port'] = 'mqtt_broker_port
app.config['cow_mq_username'] = 'mqtt_username' # option
app.config['cow_mq_password'] = 'mqtt_password' # option
app.config['cow_mq_tls_ca_certs'] = None # option
app.config['cow_mq_tls_certfile'] = None # option
app.config['cow_mq_tls_keyfile'] = None # option
```

### Server
```
from cow_mq.server import Server as CowMQServer

cow_server = CowMQServer(app, 'server_domain')

@cow_server.route('/version')
def version(payload):
    data = json.dumps({'version': '0.0.1'})
    return data.encode('utf-8')
```

**Blueprint**
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

cow_client = CowMQClient(app)

def version_callback(domain, rule, rsp_data):
    print('version async rsp: {}'.format(rsp_data))

data = json.dumps({'type': 1})
cow_client.async_send('server_domain', '/version', data.encode('utf-8'), version_callback)

```

**Listener Server Status**
```
def on_cow_mq_server_connect(domain):
    print('on_cow_mq_server_connect: {}'.format(domain))

def on_cow_mq_server_disconnect(domain):
    print('on_cow_mq_server_disconnect: {}'.format(domain))
    
cow_client.register_server_connected('server_domain')
cow_client.on_server_connect = on_cow_mq_server_connect
cow_client.on_server_disconnect = on_cow_mq_server_disconnect
```


## License

CowMQ is available under the MIT license.