# 模块类型
__type__ = "Exchange"
# 模块帮助信息
__help__ = "Exchange module"

__all__ = [__type__, __help__]

import argparse
from argparse import ArgumentParser

from plugins import PluginBase
from utils.logger import output


def enrollment_parameters(parser: ArgumentParser, exploit_plugin_type: list[PluginBase], exp_sub_name: str) -> None:
    """
    注册模块参数

    :param parser: 参数接收器
    :return: None
    """
    output.debug(f"init {__type__} parameters")

    # Exchange模块必须参数
    ad_sub_mode = parser.add_subparsers(dest="scan_type")
    scan_mode = ad_sub_mode.add_parser("scan", formatter_class=argparse.RawDescriptionHelpFormatter)

    scan_mode.add_argument("--all", help="select all plugins", action=argparse.BooleanOptionalAction, dest="all")
    scan_mode.add_argument("--plugin", help="select one or more plugin (E.G. plugin name1, plugin name 2...)",
                           nargs="+", dest="plugins")

    exploit_mode = ad_sub_mode.add_parser("exploit", formatter_class=argparse.RawDescriptionHelpFormatter)
    exp_plugin_mode = exploit_mode.add_subparsers()

    # 加载所有Exchange-exploit插件，读取参数，注册
    for e_p_t in exploit_plugin_type:
        exp_sub_plugin_mode = exp_plugin_mode.add_parser(e_p_t.alias,
                                                         formatter_class=argparse.RawDescriptionHelpFormatter)
        if e_p_t.alias == exp_sub_name:
            e_p_t.reg_argument(exp_sub_plugin_mode)


class PluginExchangeBase(PluginBase):
    def __init__(self, user_args):
        super().__init__()
