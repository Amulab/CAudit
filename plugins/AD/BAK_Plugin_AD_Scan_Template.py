from copy import copy

from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes


class PluginADXXX(PluginADScanBase):
    """

    """

    display = ""
    alias = ""
    p_type = AllPluginTypes.Scan

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        return result
