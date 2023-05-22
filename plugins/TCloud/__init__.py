import argparse
import json
import sys
from argparse import ArgumentParser

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.sts.v20180813 import sts_client as v20180813_sts_client, models as v20180813_modules
from tencentcloud.cam.v20190116 import cam_client as v20190116_cam_client, models as v20190116_modules

from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output

# 模块类型
__type__ = "TCloud"
# 模块帮助信息
__help__ = "TencentCloud module"

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


class PluginTencentCloudBase(PluginBase):
    """
    VCenter 插件基础类
    """

    def __init__(self):
        super().__init__()


class TencentAPi:
    def __init__(self, sid, sk):
        self.secret_id = sid
        self.secret_key = sk

        self.cred = credential.Credential(self.secret_id, self.secret_key)

    def get_caller_identity(self):
        cred = credential.Credential(self.secret_id, self.secret_key)
        user_id = None
        try:
            # 实例化一个http选项，可选的，没有特殊需求可以跳过
            httpProfile = HttpProfile()
            httpProfile.endpoint = "sts.tencentcloudapi.com"

            # 实例化一个client选项，可选的，没有特殊需求可以跳过
            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            # 实例化要请求产品的client对象,clientProfile是可选的
            client = v20180813_sts_client.StsClient(cred, "ap-chengdu", clientProfile)

            req = v20180813_modules.GetCallerIdentityRequest()
            params = {}
            req.from_json_string(json.dumps(params))

            resp = client.GetCallerIdentity(req)
            output.debug(f"get UserID: {resp.UserId}")
            user_id = int(resp.UserId)
        except TencentCloudSDKException as err:
            print(err)

        try:
            # 实例化一个http选项，可选的，没有特殊需求可以跳过
            httpProfile = HttpProfile()
            httpProfile.endpoint = "cam.tencentcloudapi.com"

            # 实例化一个client选项，可选的，没有特殊需求可以跳过
            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            # 实例化要请求产品的client对象,clientProfile是可选的
            client = v20190116_cam_client.CamClient(cred, "ap-chongqing", clientProfile)

            # 实例化一个请求对象,每个接口都会对应一个request对象
            req = v20190116_modules.ListAttachedUserPoliciesRequest()
            params = {
                "TargetUin": user_id
            }
            req.from_json_string(json.dumps(params))

            resp = client.ListAttachedUserPolicies(req)

            return resp.List

        except TencentCloudSDKException as err:
            print(err)
