import argparse
import base64
import json
import sys
import time
from argparse import ArgumentParser

import oss2

from plugins import PluginBase
from utils.consts import AllPluginTypes
from utils.logger import output
from Tea.core import TeaCore

from alibabacloud_ram20150501 import models as ram_20150501_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models
from alibabacloud_ram20150501.client import Client as Ram20150501Client
from alibabacloud_sts20150401.client import Client as Sts20150401Client
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_rds20140815.client import Client as Rds20140815Client
from alibabacloud_rds20140815 import models as rds_20140815_models
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util.client import Client as UtilClient
from alibabacloud_tea_util import models as util_models

# 模块类型
__type__ = "AliCloud"
# 模块帮助信息
__help__ = "AliCloud module"

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


class PluginAliCloudBase(PluginBase):
    """
    VCenter 插件基础类
    """

    def __init__(self):
        super().__init__()


class AliCloud:
    def __init__(self, ak, sk):
        self.access_key = ak
        self.secrets_key = sk

        self.config = open_api_models.Config()
        # 您的AccessKey ID
        self.config.access_key_id = self.access_key
        # 您的AccessKey Secret
        self.config.access_key_secret = self.secrets_key

    def getkeyuser(self):
        # 访问的域名
        self.config.endpoint = f'sts.cn-hangzhou.aliyuncs.com'
        client = Sts20150401Client(self.config)

        runtime = util_models.RuntimeOptions()
        try:
            # 复制代码运行请自行打印 API 的返回值
            res = client.get_caller_identity_with_options(runtime)
            return res.body.arn.split("/")[1]
        except Exception as error:
            # 如有需要，请打印 error
            output.error(error.message)
            return None

    def listpoliciesforuser(self, username):
        request = ram_20150501_models.ListPoliciesForUserRequest()
        request.user_name = username

        self.config.endpoint = f'ram.aliyuncs.com'
        client = Ram20150501Client(self.config)

        try:
            response = client.list_policies_for_user(request)
            return json.loads(UtilClient.to_jsonstring(TeaCore.to_map(response)))["body"]["Policies"]["Policy"]
        except Exception as error:
            output.error(error.message)
            return None

    def listbuckets(self):
        auth = oss2.Auth(self.access_key, self.secrets_key)
        service = oss2.Service(auth, 'https://oss-cn-hangzhou.aliyuncs.com')

        # 列举当前账号所有地域下的存储空间。
        return service

    def getallregions(self):
        self.config.endpoint = f'ecs-cn-hangzhou.aliyuncs.com'
        client = Ecs20140526Client(self.config)

        describe_regions_request = ecs_20140526_models.DescribeRegionsRequest()
        runtime = util_models.RuntimeOptions()
        try:
            # 复制代码运行请自行打印 API 的返回值
            response = client.describe_regions_with_options(describe_regions_request, runtime)
            regions_ids = [x.region_id for x in response.body.regions.region]
            return regions_ids
        except Exception as error:
            # 如有需要，请打印 error
            output.error(error.message)
            return None

    def listecs(self, region_id):
        self.config.endpoint = f'ecs-cn-hangzhou.aliyuncs.com'
        client = Ecs20140526Client(self.config)

        describe_instances_request = ecs_20140526_models.DescribeInstancesRequest(region_id=region_id)
        runtime = util_models.RuntimeOptions()
        try:
            result_lists = []
            # 复制代码运行请自行打印 API 的返回值
            response = client.describe_instances_with_options(describe_instances_request, runtime)
            if response.body.total_count != 0:
                for r in response.body.instances.instance:
                    result_lists.append([
                        r.creation_time,
                        r.description,
                        r.host_name,
                        r.instance_id,
                        r.instance_name,
                        r.osname,
                        r.ostype,
                        r.region_id,
                        r.status,
                        r.public_ip_address.ip_address
                    ])
            return result_lists

        except Exception as error:
            # 如有需要，请打印 error
            if error.statusCode != 403:
                output.error(error.message)
            return []

    def listrds(self, region_id):
        self.config.endpoint = f'rds.aliyuncs.com'
        client = Rds20140815Client(self.config)

        describe_dbinstances_request = rds_20140815_models.DescribeDBInstancesRequest(region_id=region_id)
        runtime = util_models.RuntimeOptions()
        try:
            result_lists = []
            # 复制代码运行请自行打印 API 的返回值
            resp = client.describe_dbinstances_with_options(describe_dbinstances_request, runtime)

            if resp.body.page_record_count != 0:
                for r in resp.body.items.dbinstance:
                    result_lists.append({
                        "RegionId": r.region_id,
                        "VpcId": r.vpc_id,
                        "VpcName": r.vpc_name,
                        "CreateTime": r.create_time,
                        "Engine": r.engine,
                        "EngineVersion": r.engine_version,
                        "DedicatedHostZoneIdForMaster": r.dedicated_host_zone_id_for_master,
                        "ConnectionString": r.connection_string,
                        "MasterInstanceId": r.master_instance_id,
                        "ZoneId": r.zone_id,
                        "Tips": r.tips,
                        "DBInstanceDescription": r.dbinstance_description,
                        "DBInstanceStatus": r.dbinstance_status,
                    })
            return result_lists
        except Exception as error:
            # 如有需要，请打印 error
            output.error(error.message)

    def executecommand(self, instance_id, command, region_id, os_type="linux"):
        command_id = None

        # 创建command id
        self.config.endpoint = f'ecs-cn-hangzhou.aliyuncs.com'
        client = Ecs20140526Client(self.config)
        runtime = util_models.RuntimeOptions()
        instance_type = "RunShellScript"

        if os_type == "windows":
            instance_type = "RunBatScript"

        try:
            resp = client.create_command_with_options(
                ecs_20140526_models.CreateCommandRequest(region_id=region_id, name='testName', type=instance_type,
                                                         command_content=base64.b64encode(command.encode()).decode()),
                runtime)

            command_id = resp.body.command_id
            output.debug(f"registry command: {command_id}")
        except Exception as error:
            # 如有需要，请打印 error
            output.error(error.message)
            return False

        # 执行
        execute_id = None
        try:
            output.info(f"{command}")

            resp = client.invoke_command_with_options(
                ecs_20140526_models.InvokeCommandRequest(region_id=region_id, command_id=command_id,
                                                         instance_id=[instance_id]), runtime)
            execute_id = resp.body.invoke_id
            output.debug(f"execute command: {execute_id}")
        except Exception as error:
            # 如有需要，请打印 error
            UtilClient.assert_as_string(error.message)
            return False

        # 获取结果
        try:
            get_results = False
            while not get_results:
                resp = client.describe_invocation_results_with_options(
                    ecs_20140526_models.DescribeInvocationResultsRequest(
                        region_id=region_id
                    ), runtime)
                for result in resp.body.invocation.invocation_results.invocation_result:
                    if result.invoke_record_status == "Finished" and execute_id == result.invoke_id:
                        output.success(base64.b64decode(result.output).decode())
                        get_results = True
                        break
                time.sleep(1)
        except Exception as error:
            # 如有需要，请打印 error
            UtilClient.assert_as_string(error.message)
            return False

        # 删除command id
        output.debug(f"delete command: {command_id}")

        try:
            # 复制代码运行请自行打印 API 的返回值
            resp = client.delete_command_with_options(ecs_20140526_models.DeleteCommandRequest(
                region_id=region_id,
                command_id=command_id
            ), runtime)
            if resp.status_code == 200:
                output.debug("deleted")
        except Exception as error:
            # 如有需要，请打印 error
            UtilClient.assert_as_string(error.message)
