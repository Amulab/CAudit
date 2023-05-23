import argparse
import base64
import json
import random
import string
import sys
import time
from argparse import ArgumentParser

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.sts.v20180813 import sts_client as v20180813_sts_client, models as v20180813_modules
from tencentcloud.cam.v20190116 import cam_client as v20190116_cam_client, models as v20190116_modules
from tencentcloud.cvm.v20170312 import cvm_client as v20170312_cvm_client, models as v20170312_models
from tencentcloud.lighthouse.v20200324 import lighthouse_client as v20200324_lighthouse_client, \
    models as v20200324_models
from tencentcloud.tat.v20201028 import tat_client as v20201028_tat_client, models as v20201028_models

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

    def get_all_regions(self):
        try:
            httpProfile = HttpProfile()
            httpProfile.endpoint = "cvm.tencentcloudapi.com"

            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            client = v20170312_cvm_client.CvmClient(self.cred, "", clientProfile)

            req = v20170312_models.DescribeRegionsRequest()
            params = {}
            req.from_json_string(json.dumps(params))

            resp = client.DescribeRegions(req)
            return resp.RegionSet

        except TencentCloudSDKException as err:
            output.error(err)

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
            output.error(err)

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
            output.error(err)

    def get_cvm_instance(self, region):
        regions = []
        if isinstance(region, str):
            regions.append(region)
        else:
            regions = region

        results = []

        for r in regions:
            try:
                httpProfile = HttpProfile()
                httpProfile.endpoint = "cvm.tencentcloudapi.com"

                clientProfile = ClientProfile()
                clientProfile.httpProfile = httpProfile
                client = v20170312_cvm_client.CvmClient(self.cred, r.Region, clientProfile)

                req = v20170312_models.DescribeInstancesRequest()
                params = {}
                req.from_json_string(json.dumps(params))

                output.debug(f"searching {r.Region}")

                resp = client.DescribeInstances(req)
                if len(resp.InstanceSet) != 0:
                    for x in resp.InstanceSet:
                        results.append(x)
            except TencentCloudSDKException as err:
                output.error(err)
        return results

    def get_lh_instance(self, region):
        regions = []
        if isinstance(region, str):
            regions.append(region)
        else:
            regions = region

        results = []

        for r in regions:
            try:
                httpProfile = HttpProfile()
                httpProfile.endpoint = "lighthouse.tencentcloudapi.com"

                clientProfile = ClientProfile()
                clientProfile.httpProfile = httpProfile
                client = v20200324_lighthouse_client.LighthouseClient(self.cred, r.Region, clientProfile)

                req = v20200324_models.DescribeInstancesRequest()
                params = {}
                req.from_json_string(json.dumps(params))

                output.debug(f"searching {r.RegionName}")

                resp = client.DescribeInstances(req)
                if len(resp.InstanceSet) != 0:
                    for x in resp.InstanceSet:
                        results.append(x)

            except TencentCloudSDKException as err:
                if err.args[0] != "UnsupportedRegion":
                    output.error(err)
        return results

    def lh_execute_command(self, region, instance_id, os_type, command):
        command_type = "SHELL"

        if os_type == "windows":
            command_type = "POWERSHELL"

        httpProfile = HttpProfile()
        httpProfile.endpoint = "tat.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile

        # 创建命令
        try:
            client = v20201028_tat_client.TatClient(self.cred, region, clientProfile)

            req = v20201028_models.CreateCommandRequest()
            params = {
                "CommandName": ''.join(random.sample(string.ascii_letters + string.digits, 5)),
                "CommandType": command_type,
                "Content": base64.b64encode(command.encode()).decode()
            }
            req.from_json_string(json.dumps(params))

            resp = client.CreateCommand(req)
            command_id = resp.CommandId

            output.debug(f"get command id: {command_id}")
        except TencentCloudSDKException as err:
            output.error(err)
            return False

        # 触发命令
        try:
            client = v20201028_tat_client.TatClient(self.cred, region, clientProfile)

            req = v20201028_models.InvokeCommandRequest()
            params = {
                "CommandId": command_id,
                "InstanceIds": [instance_id]
            }
            req.from_json_string(json.dumps(params))

            resp = client.InvokeCommand(req)
            invocation_id = resp.InvocationId
            output.debug(f"get invocation id: {invocation_id}")
        except TencentCloudSDKException as err:
            output.error(err)
            return False

        # 获取命令结果
        command_result_base64 = ""
        try:
            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            client = v20201028_tat_client.TatClient(self.cred, region, clientProfile)

            req = v20201028_models.DescribeInvocationTasksRequest()
            params = {
                "HideOutput": False
            }
            req.from_json_string(json.dumps(params))
            resp = client.DescribeInvocationTasks(req)

            get_resulted = False
            while not get_resulted:
                if resp.InvocationTaskSet[0].CommandId == command_id:
                    output.debug(f"get command base64 string:\n\n"
                                 f"{resp.InvocationTaskSet[0].TaskResult.Output}\n")
                    command_result_base64 = resp.InvocationTaskSet[0].TaskResult.Output
                    get_resulted = True
                else:
                    time.sleep(1)
        except TencentCloudSDKException as err:
            output.error(err)
            return False

        # 删除命令
        try:
            client = v20201028_tat_client.TatClient(self.cred, region, clientProfile)

            req = v20201028_models.DeleteCommandRequest()
            params = {"CommandId": command_id}
            req.from_json_string(json.dumps(params))

            resp = client.DeleteCommand(req)
            if resp.headers is None:
                output.debug(f"success delete {command_id}")

        except TencentCloudSDKException as err:
            output.error(err)

        return command_result_base64

    def get_lh_meta_data(self):
        pass