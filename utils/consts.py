# 默认插件模块路径

PLUGIN_DIR = "plugins"
# 插件脚本以Plugin开头. Plugin_xx_xx.py
plugin_contain_name: str = "Plugin"


class ScriptRunStatus(str):
    pass


PLUGIN_EXECUTE_SUCCESS = ScriptRunStatus("Success")
PLUGIN_EXECUTE_FAILED = ScriptRunStatus("Failed")
PLUGIN_EXECUTE_ERROR = ScriptRunStatus("Error")


# TODO 修改模块基类硬编码
# TODO 修改模块名称为小写 -2
module_base_class = {
    "AD": ["PluginADScanBase", "PluginAdExploitBase"],
    "VCenter": ["PluginVCenterBase", "PluginVCenterScanBase"],
    "Kubernetes": ["PluginKubernetesBase"],
    "Exchange": ["PluginExchangeBase"],
    "JumpServer": ["PluginJumpServerBase"],
    "Qz": ["PluginQizhiBase"],
    "Zabbix": ["PluginZabbixBase"],
    "AliCloud": ["PluginAliCloudBase"],
    "TCloud": ["PluginTencentCloudBase"]
}


class AllPluginTypes:
    Scan = "scan"
    Exploit = "exploit"


module_types = ["scan", "exploit"]
