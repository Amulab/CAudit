import argparse
import concurrent.futures
import sys
from concurrent.futures import wait, ALL_COMPLETED
from importlib import import_module

from prettytable import PrettyTable

import utils
from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output
from utils.plugin_utils import get_plugin_type, load_plugin, filter_user_plugin


def load_module_param(mod_name, exploit_plugin_name, all_module_plugins):
    parser = argparse.ArgumentParser(description="")
    subparser = parser.add_subparsers(dest="sub_mode")

    parser.add_argument("--thread", help="set thread. default=5", required=False, default=5, type=int, dest="thread")
    parser.add_argument("--save", help="save result to file. default=results.html", required=False, default="results.html",dest="save")

    # 加载模块参数
    modules = get_plugin_type()
    for m, mf in modules.items():
        if m == mod_name:
            k = import_module(mf)

            search_parser = subparser.add_parser(k.__type__, help=k.__help__,
                                                 formatter_class=argparse.RawDescriptionHelpFormatter)

            enrol_func = getattr(k, "enrollment_parameters")
            enrol_func(search_parser, all_module_plugins, exploit_plugin_name)

    if len(sys.argv) == 1:
        sys.exit(-1)

    # 获取参数
    args = parser.parse_args()
    return args


def check_print_help(m_name, p_list):
    if "--list" not in sys.argv:
        return False

    plugin_type = "all"
    if sys.argv[sys.argv.index(m_name)+1] == "scan":
        plugin_type = "scan"
    elif sys.argv[sys.argv.index(m_name)+1] == "exploit":
        plugin_type = "exploit"

    print_plugin = PrettyTable(["alias", "display"])
    print_plugin.align["alias"] = "l"
    print_plugin.align["display"] = "l"
    print_plugin.border = False
    for k, v in p_list.items():
        if plugin_type == "all":
            print_plugin.add_row([v.alias, v.display])
        else:
            if v.p_type == plugin_type:
                print_plugin.add_row([v.alias, v.display])

    output.info(f"show {plugin_type} plugin:\n"
                f"{print_plugin}")
    return True



def check_program_help():
    # 打印全局help
    h = ["-h", "--help"]
    if len(sys.argv) == 2 and sys.argv[1] in h:
        output.print_simple_help("all")


def check_debug():
    for i, v in enumerate(sys.argv):
        if v == "--debug":
            output.isDebug = True
            output.open_debug()
            output.info("debug mode opened")
            sys.argv.pop(i)
            break


if __name__ == '__main__':
    # 加载全局参数
    check_debug()

    # 检查-h/--help
    check_program_help()

    # 加载模块所有的插件
    m_name = utils.get_user_module()
    if m_name == "":
        output.print_simple_help()
        sys.exit(1)

    p_list: dict[str, PluginBase] = load_plugin(m_name)
    if len(p_list.keys()) == 0:
        output.success("No plugin loaded")
        sys.exit(1)

    # 是否只打印插件信息
    if check_print_help(m_name, p_list):
        sys.exit(0)

    # 加载模块参数
    exploit_plugin_name = utils.get_user_exploit_input()
    user_args = load_module_param(m_name, exploit_plugin_name, p_list)

    output.save = user_args.save
    output.info(f"set the result is saved to {output.save}")

    if user_args.scan_type is None:
        output.print_simple_help(user_args.sub_mode)
        sys.exit(2)

    scripts_result: dict[str, dict] = dict()

    execute_plugins = filter_user_plugin(p_list, user_args, exploit_plugin_name)

    # 执行, 多线程
    output.debug(f"Execute thread: {user_args.thread}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=user_args.thread) as executor:
        nl = ""
        temp_results = []
        results = []

        if user_args.scan_type == AllPluginTypes.Exploit:
            nl = "\n"

        for p in execute_plugins:
            output.info(f"run plugin: {output.YELLOW}{p.__module__}{output.RESET}{nl}")

            plugin_cls: PluginBase = p

            # 扫描类型插件，在此处初始化并传参
            if user_args.scan_type == "scan":
                plugin_cls: PluginBase = p(user_args)

            r = executor.submit(plugin_cls.run_script, user_args)
            temp_results.append(r)
            results.append({
                "result": r,
                "alias": plugin_cls.alias,
                "display": plugin_cls.display,
                "plugin_name": plugin_cls.__module__
            })

            # r = executor.submit(p.run_script, user_args)
            # temp_results.append(r)
            # results.append({
            #     "result": r,
            #     "alias": p.alias,
            #     "plugin_name": p.__module__
            # })
        wait(temp_results, return_when=ALL_COMPLETED)

        for r in results:
            display_value = r["display"]
            module_name = r["plugin_name"]
            module_alias = r["alias"]
            module_results = ""
            try:
                module_results = r["result"].result()
            except Exception:
                module_results = str(r['result']._exception)
                output.error(f"{module_name} execute error: {module_results}")
            scripts_result[module_name] = {
                "display": display_value,
                "alias": module_alias,
                "results": module_results
            }

    # 输出结果
    if user_args.scan_type == AllPluginTypes.Scan:
        output.show_results(scripts_result, user_args.scan_type)
