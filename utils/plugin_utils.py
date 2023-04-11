import os
import pkgutil
import sys
from importlib import import_module

from plugins import PluginBase
from utils.consts import PLUGIN_DIR, module_base_class, plugin_contain_name, AllPluginTypes
from utils.logger import output


def load_plugin(mod_name: str) -> dict:
    """
    初始化所有模块插件, 返回插件名称对应的插件类(不实例化)
    :param mod_name: 用户选择的模块名称
    :return:
    """
    output.debug(f"load module: {mod_name}")

    # 所有插件类
    plugin_class: dict[str, PluginBase] = dict()

    # 当前绝对路径，正确的情况是获取到 modules 绝对路径
    base_dir = '\\'.join(os.path.dirname(__file__).split('\\')[0:-1]) + "\\" + PLUGIN_DIR + "\\" + mod_name
    # 如果是main执行上面的os.path.dirname，返回的是空，则需要调用abspath获取绝对路径
    if not base_dir:
        base_dir = '\\'.join(os.path.dirname(os.path.abspath(__file__)).split('\\')[
                             0:-1]) + "\\" + PLUGIN_DIR + "\\" + mod_name

    if sys.platform == "darwin":
        base_dir = '/'.join(os.path.dirname(__file__).split("/")[0:-1]) + "/" + PLUGIN_DIR + "/" + mod_name

    output.debug(f"Reading plugin dir: {base_dir}")

    # 获取当前插件目录所有插件文件
    found_modules = []
    for x, file_name, _ in pkgutil.iter_modules([base_dir]):
        if str(file_name).startswith(plugin_contain_name):
            try:
                file_module = x.find_module(file_name).load_module(file_name)
                found_modules.append(file_module)
            except AttributeError as e:
                output.debug(f"import {x}.{file_name} error.")

    # 对加载的插件文件进行遍历，加载文件中的插件类
    for module in found_modules:
        plugin_cls = list(dir(module))

        # 获取插件类（同时要过滤掉基类）
        type_a_class = [x for x in plugin_cls if
                        x.startswith(plugin_contain_name) and x not in module_base_class[mod_name]]
        for class_name in type_a_class:
            # 实例化类并添加到列表
            # class_ins = getattr(module, class_name)
            # t: PluginBase = class_ins()
            #
            # 将实例化后的插件添加到列表
            # plugin_class.append(t)
            class_ins = getattr(module, class_name)
            plugin_class[class_name] = class_ins

            output.debug(f"Loading plugin: {class_name}")

    return plugin_class


# def list_plugin_info(module_name, plugin_lists: list[PluginBase]) -> None:
#     """
#     列出插件帮助信息
#
#     :param module_name: 模块名称
#     :param plugin_lists: 插件列表
#     :return: None
#     """
#     output.debug(f"show {module_name} plugin info")
#     plugin_title = ["plugin_name", "alias", "type", "parameters"]
#
#     # 创建表格
#     result_table = PrettyTable()
#     result_table.field_names = plugin_title
#
#     for p in plugin_lists:
#         # 插件参数 "a, b, c..."
#         plugin_param = ", ".join([x.strip().split(":")[2].strip() for x in p.__doc__.split("\n") if "param" in x])
#         p_type = p.p_type
#
#         # 标记错误的类型
#         if p_type not in module_types:
#             p_type = f"{p.p_type}(x)"
#
#         if len(plugin_param) > 40:
#             # 自动换行
#             result_table.add_row([p.__module__, p.alias, p_type, fill(plugin_param, width=40)])
#         else:
#             result_table.add_row([p.__module__, p.alias, p_type, plugin_param])
#
#     # 打印表格
#     output.info(f"list module {output.RED}{module_name}{output.BLUE} plugins: \n"
#                 f"{result_table}")


def get_plugin_type() -> dict[str, str]:
    """
    获取模块类型
    {
        'AD': 'plugins.AD'
    }

    :return: 模块类型列表
    """
    p_type: dict[str, str] = dict()

    plugin_dir = os.listdir(PLUGIN_DIR)
    for pd in plugin_dir:
        if os.path.isdir(f"{PLUGIN_DIR}/{pd}") and not pd.startswith("__"):
            # output.debug(f"get plugin mode: {pd}")

            k = import_module(f"{PLUGIN_DIR}.{pd}")
            p_type[k.__type__] = f"{PLUGIN_DIR}.{pd}"

    return p_type


def get_exploit_plugin(all_plugins: dict) -> list[PluginBase]:
    a = [plugin for n, plugin in all_plugins.items() if plugin.p_type == AllPluginTypes.Exploit]
    return a


def filter_user_plugin(all_plugins: dict, user_args, select_plugin) -> list[PluginBase]:
    """
    过滤出要运行的插件类别
    :param all_plugins: 所有已加载的插件
    :param user_args: 用户输入参数
    :return: 过滤后的插件列表
    """
    execute_plugins = []
    for n, p in all_plugins.items():
        if user_args.scan_type == AllPluginTypes.Scan and user_args.scan_type == p.p_type:
            execute_plugins.append(p)
        elif user_args.scan_type == AllPluginTypes.Exploit and p.alias == select_plugin:
            execute_plugins.append(p)
    return execute_plugins
