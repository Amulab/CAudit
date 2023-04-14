import datetime
import struct
import time
from copy import copy
from ldap3 import SUBTREE


# FILE_TIME_EPOCH = datetime.datetime(1601, 1, 1, 8)  # 加了 8 小时，如果没有8这个参数，那么转换出来的值将会比正常值少8小时
from plugins.AD import PluginADScanBase
from utils.consts import AllPluginTypes

FILE_TIME_EPOCH = datetime.datetime(1601, 1, 1)
FILE_TIME_MICROSECOND = 10


def convert_from_file_time(file_time):
    microseconds_since_file_time_epoch = file_time // FILE_TIME_MICROSECOND
    return FILE_TIME_EPOCH + datetime.timedelta(
        microseconds=microseconds_since_file_time_epoch)


class PluginADBackupMetadata(PluginADScanBase):
    """根据Microsoft标准发现上次备份日期太长"""
    display = "根据Microsoft标准发现上次备份日期太长"
    alias = "BackupMetadata"
    p_type = AllPluginTypes.Scan

    def verify2(self, *args, **kwargs):

        query = "(objectClass=domain)"
        attributes = ["cn", "whenCreated"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            whenCreated = entry["attributes"]["whenCreated"]
            whenCreated1, whenCreated2, whenCreated3 = (str(whenCreated).partition(' '))
            time_whenCreated = time.strptime(whenCreated1, "%Y-%m-%d")
            time_whenCreated = datetime.datetime(time_whenCreated[0], time_whenCreated[1], time_whenCreated[2])
            return time_whenCreated



    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_script(self, args) -> dict:
        result = copy(self.result)
        update_day = int(self.meta_data["update_day"])
        instance_list = []
        data = {}
        data["replPropertyMetaData"] = []

        query = "(&(objectClass=domain)(replPropertyMetaData=*))"  # 过滤出域对象，并且存在属性replPropertyMetaData。  replPropertyMetaData用来跟踪 DS 对象的内部复制状态信息
        attributes = ["cn", "replPropertyMetaData"]

        entry_generator = self.ldap_cli.con.extend.standard.paged_search(search_base=self.ldap_cli.domain_dn,
                                                                         search_filter=query,
                                                                         search_scope=SUBTREE,
                                                                         get_operational_attributes=True,
                                                                         attributes=attributes,
                                                                         paged_size=1000,
                                                                         generator=True)

        for entry in entry_generator:
            if entry["type"] != "searchResEntry":
                continue
            record_count, = struct.unpack(
                "<I", entry["attributes"]["ReplPropertyMetaData"][8:12])
            pointer = 16
            fmt = f"<2IQ16s2Q"
            for _ in range(record_count):
                attr_type, version, filetime, guid, UsnOriginatingChange, UsnLocalChange = struct.unpack(
                    fmt, entry["attributes"]["ReplPropertyMetaData"][pointer:pointer + 48])
                pointer += 48
                filetime = filetime + 28800  # +28800 如果不加结果将会比正确时间少8个小时
                if 0x2004a == attr_type:  # 0x2004a代表什么 ->  dSASignature
                    date = (convert_from_file_time(
                        int(filetime) * 10000000))  # ReplPropertyMetaData属性中的时间
                    time_whenCreated = self.verify2()  # 创建该域的日期
                    maxdatevalue = '9999-12-31 23:59:59'  # 定义了系统最大时间
                    if str(date) < maxdatevalue:
                        num_days1 = datetime.datetime.now() - date  # 系统当前时间 - ReplPropertyMetaData属性中的时间
                        if num_days1.days > update_day:  # 大于90天，就认为上次备份日期太长
                            result['status'] = 1
                            instance = {}
                            instance['backup_Date'] = date
                            instance_list.append(instance)

                    elif str(date) == maxdatevalue:  # 自从创建域，如果从来没有备份过，那么ReplPropertyMetaData属性中的时间应该为maxdatevalue
                        num_days2 = datetime.datetime.now() - time_whenCreated  # 系统当前时间 - 创建该域的时间(ReplPropertyMetaData属性中的时间等于了最大时间，所以这里减创建域的时间)
                        if num_days2.days > update_day:  # 我们认为ReplPropertyMetaData属性中的时间和maxdatevalue相等，num_days2.days大于90，就认为从未备份过
                            result['status'] = 1
                            instance = {}
                            instance['backup_Date'] = "从未备份过"
                            instance_list.append(instance)

        result['data'] = {"instance_list": instance_list}
        return result
