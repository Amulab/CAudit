import logging
from textwrap import fill

import colorama
import colorlog
from colorama import Fore
from modules.adi_lib.common.log import logger

__doc__ = """
日志记录, 输出到控制台和文件. BaseScreen为基类, Output类继承该类并重写
写入文件功能暂未实现

Example:
    output.info("information")
    output.info(f"test: {output.RED}information{output.RESET}")
    output.success("success")
    output.error("error")
"""

from prettytable import PrettyTable
from utils import module_base_class


class BaseScreen:
    BLACK = Fore.BLACK
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Fore.RESET

    prefix_info = f"{BLUE}[*]"
    prefix_success = f"{GREEN}[+]"
    prefix_error = f"{RED}[-]"
    prefix_debug = f"{CYAN}[*]"

    log_color = {
        "DEBUG": "blue",
        "INFO": "blue",
        "WARNING": "blue",
        "ERROR": "blue",
        "CRITICAL": "blue",
    }

    def __init__(self, fmt: str = '%(asctime)s %(filename)s:%(lineno)d %(message)s', datefmt: str = '%Y-%m-%d %H:%M'):
        # 初始化颜色
        colorama.init(autoreset=True)

        # 屏幕输出器 - 基本输出器
        # self.screenFormat = logging.Formatter(fmt=fmt, datefmt=datefmt)
        self.screenFormat = colorlog.ColoredFormatter(fmt='%(log_color)s' + fmt, datefmt=datefmt,
                                                      log_colors=self.log_color)
        self.screenHandle = logging.StreamHandler()
        self.screenHandle.setFormatter(self.screenFormat)
        self.screenLogger = logging.getLogger("screen")
        self.screenLogger.setLevel(logging.INFO)
        self.screenLogger.addHandler(self.screenHandle)

    def info(self, string):
        self.screenLogger.info(f"{self.prefix_info} {string}")
        # logger.info(string)

    def success(self, string):
        self.screenLogger.info(f"{self.prefix_success} {string}")
        logger.info(string)

    def error(self, string):
        self.screenLogger.error(f"{self.prefix_error} {string}")
        logger.error(string)

    def debug(self, string):
        self.screenLogger.debug(f"{self.prefix_debug} {string}")
        logger.debug(string)

    def open_debug(self):
        self.screenLogger.setLevel(logging.DEBUG)


class Output(BaseScreen):
    def __init__(self):
        super().__init__(fmt='%(message)s')
        self.isDebug = False

    def print_help(self, mod=""):
        if mod == "":
            print(f"valid module:")
            [print(f'{"":^4}{x}') for x in module_base_class.keys()]
        else:
            print(f"{mod} sub command:\n"
                  f"{'':^4}scan\n"
                  f"{'':^4}exploit")

    def print_script_run_result(self, results: dict) -> None:
        """
        以表格形式输出结果
        :param results: 收集的结果，字典
        :return: None
        """

        # root节点
        success_plugin_nodes = []
        title = ["Plugin Name", "Status", "Result"]
        run_status_string = ["Failed", "Success", "Error"]

        result_table = PrettyTable(title)
        result_table.align["Plugin Name"] = "l"

        for plugin_name, v in results.items():
            try:
                status = run_status_string[v["results"]["status"]]

                # 将结果转化为str
                result_value = ""
                for ins in v["results"]["data"]["instance_list"]:
                    for k, val in ins.items():
                        # TODO 将结果加到HTML报告, xray html 模板
                        result_value += f"{k}: {str(val)}\n"

                # 添加攻击链节点
                if status == "Success":
                    success_plugin_nodes.append(v["alias"])
            except TypeError:
                status = run_status_string[-1]
                result_value = v["results"]

            if len(result_value) > 40:
                # 自动换行
                result_table.add_row([plugin_name, status, fill(result_value.strip(), width=40)])
            else:
                result_table.add_row([plugin_name, status, result_value.strip()])

        # 打印表格 TODO 删除表格边框
        output.success(f"script results{output.RESET}\n"
                    f"{result_table}\n")

        # TODO 打印结果路径

        self.info("Attack chains:")
        self.debug(f"get attack root chain node: {success_plugin_nodes}")

        from utils.attack_chain import AttackChains

        a_chains = AttackChains()
        for n in success_plugin_nodes:
            a_chains.match(n)
        a_chains.print_chains()


output = Output()
