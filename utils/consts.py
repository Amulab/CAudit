# 默认插件模块路径
PLUGIN_DIR = "plugins"
# 插件脚本以Plugin开头. Plugin_xx_xx.py
plugin_contain_name: str = "Plugin"


class ScriptRunStatus(str):
    pass


PLUGIN_EXECUTE_SUCCESS = ScriptRunStatus("Success")
PLUGIN_EXECUTE_FAILED = ScriptRunStatus("Failed")
PLUGIN_EXECUTE_ERROR = ScriptRunStatus("Error")


class ADPluginAlias:
    # exploit
    UserEnum = "user_enum"
    PassBrute = "password_brute"
    PassSpraying = "password_spraying"
    ASReproasting = "as_reproasting"
    GetSPN = "get_spn"
    ConstrainedDelegate = "constrained_delegation"
    PsExec = "ps_exec"
    SmbExec = "smb_exec"
    WmiExec = "wmi_exec"

    # test
    Test1 = "test1"
    Test2 = "test2"
    Test3 = "test3"


# TODO 修改模块基类硬编码
module_base_class = {
    "AD": ["PluginAdBase", "PluginADScanBase", "PluginAdExploitBase"],
    "VCenter": ["PluginVCenterBase"],
    "Kubernetes": ["PluginKubernetesBase"],
    "Exchange": ["PluginExchangeBase"],
    "JumpServer": ["PluginJumpServerBase"]
}


class AllPluginTypes:
    Scan = "scan"
    Exploit = "exploit"


module_types = ["scan", "exploit"]
