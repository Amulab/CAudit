import argparse
from copy import copy

from plugins.Exchange import PluginExchangeBase
from utils import output
from utils.consts import AllPluginTypes


class PluginExchange(PluginExchangeBase):
    display = "xx"
    alias = "xx"
    p_type = AllPluginTypes.Exploit

    def __init__(self):
        super().__init__()

    def reg_argument(self, parser: argparse.ArgumentParser):
        parser.description = self.display

    def run_script(self, args) -> dict:
        """
        脚本入口函数
        :return: bool
        """
        result = copy(self.result)

        return result
