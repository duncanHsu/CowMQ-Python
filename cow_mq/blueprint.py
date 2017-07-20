from enum import Enum
from cow_mq.util import Util


class BlueprintRouteState(Enum):
    NONE = 0
    ADD = 1
    DEL = 2
    CLEAR = 3


class Blueprint:
    name = None
    import_name = None

    rule_fun_dic = None
    route_change_cb = None

    def __init__(self, name, import_name):
        self.name = name
        self.import_name = import_name
        self.rule_fun_dic = {}

    def route_change_callback(self, cb):
        self.route_change_cb = cb

    def add_route(self, rule, f):
        if rule is not None and not Util.can_use_rule(rule):
            raise Exception(
                'Blurprint rule({}) can not be use'.format(rule))

        if rule is None or f is None:
            return False
        if self.exist_route(rule):
            return False
        self.rule_fun_dic[rule] = f

        if self.route_change_cb:
            self.route_change_cb(BlueprintRouteState.ADD, rule, f)
        return True

    def remove_route(self, rule):
        if rule is None:
            return False
        if not self.exist_route(rule):
            return False
        del self.rule_fun_dic[rule]

        if self.route_change_cb:
            self.route_change_cb(BlueprintRouteState.DEL, rule, None)

    def exist_route(self, rule):
        if rule in self.rule_fun_dic:
            return True
        return False

    def clear_route(self):
        self.rule_fun_dic = {}

        if self.route_change_cb:
            self.route_change_cb(BlueprintRouteState.CLEAR, None, None)
        return True

    def route_list(self):
        return list(self.rule_fun_dic.keys())

    def route(self, rule):
        def decorator(f):
            if not self.add_route(rule, f):
                raise Exception(
                    'Blueprint route rule({}) is exist'.format(rule))
            return f
        return decorator
