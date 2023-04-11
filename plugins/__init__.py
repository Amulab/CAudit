import argparse


class PluginBase:
    # 插件中文描述
    display = ""
    # 插件英文别名
    alias = None
    # 插件类型
    p_type = None

    def __init__(self):
        """
        self.data = {
            "instance_list": [
                {
                    "key":"value",
                    "key2": "value2",
                    ...
                }
            ]
        }
        """
        self.result = {
            "status": 0,  # 0=失败 1=成功 -1=插件报错
            "data": {
                "instance_list": list[dict[str, str]]
            },
            "desc": "",
            "error": "",
        }

    def run_script(self, args) -> dict:
        """
        默认运行脚本函数, 子类重写该方法
        :param args:
        :return:
        """
        pass

    def reg_argument(self, parser: argparse.ArgumentParser):
        """
        注册参数
        :param parser:
        :return:
        """
        pass
