import argparse
import sys
from argparse import ArgumentParser

from modules.huaweiapi.obs import ObsClient
from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output

# 模块类型
__type__ = "HWCloud"
# 模块帮助信息
__help__ = "HuaweiCloud module"

__all__ = [__type__, __help__]


def enrollment_parameters(parser: ArgumentParser, all_plugins: dict[str, PluginBase], exp_sub_name: str) -> None:
    """
    注册模块参数

    :param parser: 参数接收器
    :return: None
    """
    output.debug(f"init {__type__} parameters")

    # VCenter-scan 模块
    ad_sub_mode = parser.add_subparsers(dest="scan_type")

    exploit_mode = ad_sub_mode.add_parser("exploit", formatter_class=argparse.RawDescriptionHelpFormatter)
    exp_plugin_mode = exploit_mode.add_subparsers()

    # 加载所有exploit插件，读取参数，注册
    for name, exp in all_plugins.items():
        if exp.p_type == AllPluginTypes.Exploit:
            exp_sub_plugin_mode = exp_plugin_mode.add_parser(exp.alias,
                                                             formatter_class=argparse.RawDescriptionHelpFormatter)
        # 防止没有输入alice的错误
        if exp.alias != "" and exp.alias == exp_sub_name:
            c: PluginBase = exp()
            all_plugins[name] = c

            try:
                c.reg_argument(exp_sub_plugin_mode)
            except argparse.ArgumentError as e:
                output.error(f"{name} argument error: {e}")
                sys.exit(-2)


class PluginHuaWeiCloudBase(PluginBase):
    """
    VCenter 插件基础类
    """

    def __init__(self):
        super().__init__()


class HuaweiCloudApi:
    def __init__(self, ak, sk):
        self.access_key = ak
        self.secret_key = sk

    def create_bucket(self, bucket_name, location):
        try:
            server = 'https://obs.other-region.myhuaweicloud.com'
            obsClient = ObsClient(access_key_id=self.access_key, secret_access_key=self.secret_key, server=server)
            resp = obsClient.createBucket(bucketName=bucket_name, location=location)

            if resp.status < 300:
                output.success(f'success: {resp.requestId}')
            else:
                output.error('errorCode:', resp.errorCode)
                output.error('errorMessage:', resp.errorMessage)
        except Exception as e:
            output.error(e)

    def get_bucket_lists(self):
        bucket_lists = []
        try:
            resp = ObsClient.listBuckets(True)
            if resp.status < 300:
                output.debug(f'requestId:   {resp.requestId}\n'
                             f'name:        {resp.body.owner.owner_id}\n'
                             f'create_date: {resp.body.owner.owner_name}')
                for bucket in resp.body.buckets:
                    bucket_lists.append([bucket.name, bucket.create_date, bucket.location])
            else:
                output.error('errorCode:', resp.errorCode)
                output.error('errorMessage:', resp.errorMessage)
        except Exception as e:
            output.error(e)
            return bucket_lists
        return bucket_lists
