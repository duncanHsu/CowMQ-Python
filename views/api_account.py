from cow_mq.blueprint import Blueprint as CowMQBlueprint

import json

api_account_bp = CowMQBlueprint('api_account', __name__)


@api_account_bp.route("/sign_in")
def sign_in(payload):
    # print('sign_in:{}'.format(payload))

    data = json.dumps({'token': 'abcde123456'})
    return data.encode('utf-8')
