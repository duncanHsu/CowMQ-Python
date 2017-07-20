# GowMQ
The GowMQ is a simple client-server protocol over MQTT for Python


## Other platforms
* [GowMQ-Nodejs](https://github.com/duncanHsu/GowMQ-Nodejs)
* [GowMQ-iOS](https://github.com/duncanHsu/GowMQ-iOS)
* [GowMQ-Android](https://github.com/duncanHsu/GowMQ-Android)

## How to install
> pip install GowMQ

## How to use
### Config
```
app.config['gow_mq_ip'] = 'mqtt_borker_ip'
app.config['gow_mq_port'] = 'mqtt_broker_port
app.config['gow_mq_username'] = 'mqtt_username' # option
app.config['gow_mq_password'] = 'mqtt_password' # option
```

### Server
```
from gow_mq.server import Server as GowMQServer

gow_server = GowMQServer(app, 'server_domain')

@gow_server.route('/version')
def version(payload):
    data = json.dumps({'version': '0.0.1'})
    return data.encode('utf-8')
```

**Blueprint**
```
from views.api_account import api_account_bp

gow_server.register_blueprint(api_account_bp, url_prefix='/account')
```

api_account.py
```
from gow_mq.blueprint import Blueprint as GowMQBlueprint

api_account_bp = GowMQBlueprint('api_account', __name__)

@api_account_bp.route("/sign_in")
def sign_in(payload):
    data = json.dumps({'token': 'abcde123456'})
    return data.encode('utf-8')
```

### Client
```
from gow_mq.client import Client as GowMQClient

gow_client = GowMQClient(app)

def version_callback(domain, rule, rsp_data):
    print('version async rsp: {}'.format(rsp_data))

data = json.dumps({'type': 1})
gow_client.async_send('server_domain', '/version', data.encode('utf-8'), version_callback)

```

**Listener Server Status**
```
def on_gow_mq_server_connect(domain):
    print('on_gow_mq_server_connect: {}'.format(domain))

def on_gow_mq_server_disconnect(domain):
    print('on_gow_mq_server_disconnect: {}'.format(domain))
    
gow_client.register_server_connected('server_domain')
gow_client.on_server_connect = on_gow_mq_server_connect
gow_client.on_server_disconnect = on_gow_mq_server_disconnect
```


## License

GowMQ is available under the MIT license.
