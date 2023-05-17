import argparse
import json
import sys
from argparse import ArgumentParser

import requests
from prettytable import PrettyTable

from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output

# 模块类型
__type__ = "JumpServer"
# 模块帮助信息
__help__ = "JumpServer module"

__all__ = [__type__, __help__]


def enrollment_parameters(parser: ArgumentParser, all_plugins: dict[str, PluginBase], exp_sub_name: str) -> None:
    """
    注册模块参数

    :param parser: 参数接收器
    :return: None
    """
    output.debug(f"init {__type__} parameters")

    ad_sub_mode = parser.add_subparsers(dest="scan_type")

    exploit_mode = ad_sub_mode.add_parser("exploit", formatter_class=argparse.RawDescriptionHelpFormatter)
    exp_plugin_mode = exploit_mode.add_subparsers()

    # 加载所有exploit插件，读取参数，注册
    for name, exp in all_plugins.items():
        if exp.p_type == AllPluginTypes.Exploit:
            exp_sub_plugin_mode = exp_plugin_mode.add_parser(exp.alias,
                                                             formatter_class=argparse.RawDescriptionHelpFormatter)
        # 防止没有输入alice的错误
        if exp.alias != "" and exp.alias == exp_sub_name:
            c: PluginBase = exp()
            all_plugins[name] = c

            try:
                c.reg_argument(exp_sub_plugin_mode)
            except argparse.ArgumentError as e:
                output.error(f"{name} argument error: {e}")
                sys.exit(-2)


class PluginJumpServerBase(PluginBase):
    """
    JumpServer 插件基础类
    """

    def __init__(self):
        super().__init__()


class JumpServerApi:
    def __init__(self, url, username, password, token=None):
        self.url = url
        self.token = token

        if self.token is None:
            self.token = self._auth(username, password)

    def _auth(self, username, password):
        url = self.url + '/api/v1/authentication/auth/'
        response = requests.post(url, data={
            "username": username,
            "password": password
        })
        return json.loads(response.text)['token']

    def getAllAssetsInfo(self, is_json_result):
        url = self.url + "/api/v1/assets/assets/suggestions/"
        response = requests.get(url, headers={
            "Authorization": 'Bearer ' + self.token,
            'X-JMS-ORG': '00000000-0000-0000-0000-000000000002'
        })

        if not is_json_result:

            title = ["id", "hostname", "ip", "platform", "is_active", "comment", "admin_user", "admin_user_display",
                     "created_by"]
            result_table = PrettyTable(title)

            for asset in json.loads(response.text):
                result_table.add_row([
                    asset["id"],
                    asset["hostname"],
                    asset["ip"],
                    asset["platform"],
                    asset["is_active"],
                    asset["comment"],
                    asset["admin_user"],
                    asset["admin_user_display"],
                    asset["created_by"]
                ])

            output.success(f"result: \n"
                           f"{result_table}")
        else:
            output.success(json.dumps(json.loads(response.text), indent=2))
