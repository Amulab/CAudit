# # coding=utf-8

# from enum import unique, Enum


# @unique
# class PluginPackageManager(Enum):
#     category = ("leak", "baseline")  # 插件分类:漏洞、基线
#     sub_type = ("information_leakage", "command_execution", "privilege_escalation", "invasion_legacy",
#                 "improper_configuration")  # 插件漏洞类型: 信息泄露,命令执行,权限提升,入侵遗留,配置不当
#     version = "1.0.0"  # 插件版本
#     status = ("run", "stop", "delete")  # 插件状态 run|stop|delete
#     enable = (0, 1)  # 插件是否开启（默认不开启）0 关闭 1 开启
#     ext_type = (".py2", ".python3", ".so", ".dll", ".bin", ".exe")  # 插件类型 .py2|.python3|.so|.dll|.bin|.exe
#     risk_level = (2, 3, 4, 5)  # 插件风险等级2,3,4,5 ->低危、中危、高危、严重
#     platform = ("linux", "windows")  # 插件运行平台:linux|windows


# VERIFY_RESPONSE = {
#     "status": 0,  # 0 没有漏洞 1有漏洞 -1是插件报错了
#     "data": {},
#     "desc": "",
#     "error": "",
# }
