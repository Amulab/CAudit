import argparse
import sys
from argparse import ArgumentParser

from modules.adi_lib.plugin.base import BaseSearch
from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output

# 模块类型
__type__ = "VCenter"
# 模块帮助信息
__help__ = "VCenter module"

__all__ = [__type__, __help__]


def enrollment_parameters(parser: ArgumentParser, all_plugins: dict[str, PluginBase], exp_sub_name: str) -> None:
    """
    注册模块参数

    :param parser: 参数接收器
    :return: None
    """
    output.debug(f"init {__type__} parameters")

    # VCenter-scan 模块
    ad_sub_mode = parser.add_subparsers(dest="scan_type")
    scan_mode = ad_sub_mode.add_parser("scan", formatter_class=argparse.RawDescriptionHelpFormatter)

    scan_mode_group = scan_mode.add_mutually_exclusive_group(required=True)
    scan_mode_group.add_argument("--all", help="select all plugins", action=argparse.BooleanOptionalAction, dest="all")
    scan_mode_group.add_argument("--plugin", help="select one or more plugin (E.G. plugin name1, plugin name 2...)",
                                 nargs="+", dest="plugins")
    scan_mode.add_argument("-U", "--username", required=True, default=None, dest="username")
    scan_mode.add_argument("-P", "--password", required=True, default=None, dest="password")
    scan_mode.add_argument("-I", "--ip", required=True, default=None, dest="target_ip")
    scan_mode.add_argument("-D", "--domain", required=True, default=None, help="domain name. Format: domain.com",
                           dest="domain_name")

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


class PluginVCenterBase(PluginBase):
    """
    VCenter 插件基础类
    """

    def __init__(self):
        super().__init__()


class PluginVCenterScanBase(PluginBase, BaseSearch):
    def __init__(self, *args, **kwargs):
        uarg = args[0]

        dc_conf = {
            "ldap_conf": {
                "password": uarg.password,
                "user": f"{uarg.username}@{uarg.domain_name}",
            },
            "ip": uarg.target_ip,
        }

        meta_data = {
        }
        env = {}

        super(BaseSearch, self).__init__(dc_conf, meta_data, env)
