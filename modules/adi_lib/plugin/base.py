# coding: utf-8

import json
import os
import traceback
from modules.adi_lib.common.log import logger
from modules.adi_lib.common.util import lazy_property
# from modules.adi_lib.database.mongo_cli import Collection
# from modules.adi_lib.database.redis_cli import RedisClient
from modules.adi_lib.ldap.search import LDAPSearch
from copy import deepcopy


class Base(object):
    """
    插件基类
    >>> m = Base()
    """

    def __init__(self, dc_conf, meta_data, env):
        """
        TODO 删除不必要注释
        dc_conf:
        {
            'ldap_conf': {
                'dn': 'DC=spark,DC=com',
                'password': 'Zawx@2023',
                'user': 'spark\\Administrator',
                'DNS': '192.168.31.84',
                'server': 'ldap://test-computer.spark.com'
            },
            'name': 'spark.com',
            'ip': '192.168.31.84',
            'hostname': 'TEST-COMPUTER',
            'fqdn': 'TEST-COMPUTER.spark.com',
            'platform': 'Windows Server 2012 R2 Datacenter'
        }

        meta_data:
        {
            'port': '445',
            'key2': 'value2'
        }

        env:
        {
            'redis_conf': {
                'uri': 'redis://:XVMhPmZIAfiwc4k4ZQ@192.168.30.167:6379/0'
            },
           'mongo_conf': {
                'host': '192.168.30.167:27017',
                'password': 'Aqm3GzSaw2dYABncD',
                'user': 'user_adm',
                'db_name': 'db_adm'
            }
        }

        :param dc_conf: 域控详细信息
        :param meta_data: 插件元信息
        :param env: 环境配置信息 包含redis mongo 连接信息
        """
        self.dc_conf = dc_conf
        self.dc_domain = dc_conf.get("name")
        self.dc_fqdn = dc_conf.get("fqdn")
        self.dc_hostname = dc_conf.get("hostname")
        self.dc_ip = dc_conf.get("ip")
        self.dc_platform = dc_conf.get("platform")
        self.ldap_conf = dc_conf.get("ldap_conf")
        self.meta_data = meta_data
        self.env = env
        self.result = {
            "status": 0,  # 0 没有漏洞 1有漏洞 -1是插件报错了
            "data": {},
            "desc": "",
            "error": "",
        }

    @lazy_property
    def ldap_username(self):
        if "@" in self.ldap_conf["user"]:
            username = self.ldap_conf["user"].split("@")[0]
        else:
            username = self.ldap_conf["user"].split("\\")[-1]
        return username

    @lazy_property
    def ldap_user_password(self):
        return self.ldap_conf["password"]

    @lazy_property
    def info(self):
        return self.get_info()

    @classmethod
    def get_info(cls, pack_path=None):
        """
        返回插件的定义
        :return: dict
        """
        ret = {}
        try:
            if not pack_path:
                print(cls.__module__)
                if ".main" in cls.__module__:
                    current_dir = os.path.dirname(os.path.abspath([cls.__module__][0]))
                    pack_path = os.path.join(current_dir, "plugins",
                                             cls.__module__.replace("main", "").replace(".", "/"),
                                             "package.json")
                else:
                    current_dir = os.path.dirname(os.path.abspath([cls.__module__][0]))
                    pack_path = os.path.join(current_dir, "package.json")

            with open(pack_path, 'r') as f:
                ret = json.load(f)
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
        return ret


class BaseSearch(Base):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @lazy_property
    def ldap_cli(self):
        server_prefix = self.ldap_conf["server"].split(":")[0]
        ldap_conf = deepcopy(self.ldap_conf)
        ldap_conf["server"] = server_prefix + "://" + self.dc_ip
        return LDAPSearch(self.dc_domain, ldap_conf)

    # @lazy_property
    # def mongo_cli(self):
    #     return Collection(self.env["mongo_conf"])

    # @lazy_property
    # def redis_cli(self):
    #     return RedisClient(self.env["redis_conf"])

    @lazy_property
    def info(self):
        return self.get_info()

    @classmethod
    def get_info(cls, pack_path=None):
        """
        返回插件的定义
        :return: dict
        """
        ret = {}
        try:
            if not pack_path:
                if ".main" in cls.__module__:
                    current_dir = os.path.dirname(os.path.abspath([cls.__module__][0]))
                    pack_path = os.path.join(current_dir, "plugins",
                                             cls.__module__.replace("main", "").replace(".", "/"),
                                             "package.json")
                else:
                    current_dir = os.path.dirname(os.path.abspath([cls.__module__][0]))
                    pack_path = os.path.join(current_dir, "package.json")
            with open(pack_path, 'r') as f:
                ret = json.load(f)
        except Exception as e:
            logger.error(str(e))
            logger.error(traceback.format_exc())
        return ret
