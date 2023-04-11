# coding: utf-8

import base64
import hashlib
import time
from datetime import datetime, timedelta
from importlib import import_module

import simplejson
from dns import resolver
from IPy import IP


def lazy_property(func):
    attr_name = "_lazy_" + func.__name__

    @property
    def _lazy_property(self):
        if not hasattr(self, attr_name):
            setattr(self, attr_name, func(self))

        return getattr(self, attr_name)

    return _lazy_property

class Singleton(type):
    def __init__(cls, name, bases, attrs):
        super(Singleton, cls).__init__(name, bases, attrs)
        cls._instance = None

    def __call__(cls, *args, **kw):
        if cls._instance is None:
            cls._instance = super(Singleton, cls).__call__(*args, **kw)
        return cls._instance


def load_object(path):
    """Load an object given its absolute object path, and return it.

    object can be a class, function, variable or an instance.
    path ie: 'pandas.DataFrame'
    """

    try:
        dot = path.rindex('.')
    except ValueError:
        raise ValueError("Error loading object '%s': not a full path" % path)

    module, name = path[:dot], path[dot + 1:]
    mod = import_module(module)

    try:
        obj = getattr(mod, name)
    except AttributeError:
        raise NameError("Module '%s' doesn't define any object named '%s'" %
                        (module, name))

    return obj


def md5(target):
    m2 = hashlib.md5()
    m2.update(target.encode('utf-8'))
    return m2.hexdigest()


def base64_encode(str_):
    """
    :param str_: dict/list/str/bytes
    :return: str
    """
    if isinstance(str_, dict) or isinstance(str_, list):
        str_ = simplejson.dumps(str_)

    if isinstance(str_, str):
        str_ = bytes(str_, encoding="utf-8")

    res = base64.b64encode(str_)

    return res.decode("utf-8")


class Time:
    def __init__(self):
        self.sTime = None
        self.eTime = None
        self.start = None

    def now(self, format="%Y-%m-%d %H:%M:%S", is_UTC=False):
        if not is_UTC:
            return time.strftime(format, time.localtime(time.time()))
        else:
            return time.strftime(format, time.localtime(time.time()))

    def day(self):
        return time.strftime("%Y-%m-%d", time.localtime(time.time()))

    def consoleNow(self):
        return time.strftime("%a %b %d %H", time.localtime(time.time()))

    def getTimeByCustom(self, format, postime=0):
        return time.strftime(format, time.localtime(time.time() + postime))

    def strTimeToDigital(self, strtime, format="%Y %a %b %d %H:%M"):
        return time.mktime(time.strptime(strtime, format))

    def getDigitalTimeByCustom(self, postime=0):
        return time.localtime(time.time() + postime)

    def timestamps(self):
        return time.time()

    def year(self):
        return time.strftime("%Y", time.localtime(time.time()))

    def setStartTime(self):
        self.sTime = time.time()

    def setEndTime(self):
        self.eTime = time.time()

    def getCostTime(self):
        return self.eTime - self.sTime

    def printCostTime(self, mark=""):
        print("%s Cost Time : %s sec" % (mark, self.eTime - self.sTime))

    def printCostBigTime(self, mark="", big=3):
        cost = self.eTime - self.sTime
        if int(cost) >= big:
            print("%s Cost Time : %s sec" % (mark, cost))

    def is_passTime(self, intervalTime=3):  # 是否过了一定时间
        if time.time() - self.start > intervalTime:
            self.start = time.time()
            return 1
        else:
            return 0


def datetime_now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def datetime_now_obj():
    return datetime.now()


def get_n_days_ago(n):
    """
        获取n天之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(days=num)


def get_n_hour_ago(n):
    """
        获取n小时之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(hours=num)


def get_n_min_ago(n):
    """
        获取n分钟之前的datetime对象
    """
    num = -int(n)
    return datetime.now() + timedelta(minutes=num)


def move_n_sec(date_time, n):
    return date_time + timedelta(seconds=-n)


def move_n_min(date_time, n):
    return date_time + timedelta(minutes=-n)


def move_n_hour(date_time, n):
    return date_time + timedelta(hours=-n)


def move_n_day(date_time, n):
    return date_time + timedelta(days=-n)


def date_time_to_time(time):
    """
        将datetime对象转换为常见的时间格式
    """
    return time.strftime('%Y-%m-%d %H:%M:%S')


def datetime_to_log_date(date_time):
    return date_time.strftime('%Y.%m.%d')


def utc_to_local_datetime(utc_str):
    """
        暴力方法，直接将时间加8小时得到当前本地时间
    """
    a = datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    return a + timedelta(hours=8)


def utc_to_datetime(utc_str):
    """
        UTC格式时间转化为datetime对象
    """
    return datetime.strptime(utc_str, "%Y-%m-%dT%H:%M:%S.%fZ")


def str_to_datetime(utc_str):
    """
        字符串时间转化为datetime对象
    """
    return datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")


def datetime_to_utc(date_time):
    """
        将datetime对象转换为UTC时间格式
    """
    return date_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def datetime_to_utc_no_f(date_time):
    """
        将datetime对象转换为UTC时间格式
    """
    return date_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def convert_nested_to_list(nested, key):
    result = []
    for each in nested:
        result.append(each[key])
    return result


def hex2bin_number(number_str):
    n = int(number_str.upper(), 16)
    return bin(n)


def ip_filter(ip):
    if ip == "-" or ip == "::1":
        return True
    try:
        ip = IP(ip)
    except Exception as e:
        return True
    if ip in IP("127.0.0.0/8"):
        return True
    if ip.iptype() not in ["PRIVATE", "PUBLIC"]:
        return True


def get_netbios_domain(domain):
    if "." not in domain:
        return domain.upper()
    elif "." in domain:
        prefix = domain.split(".")[0]
        return prefix.upper()


def cost_time(func):
    """
    装饰器 统计各个type的操作耗时
    :return:
    """

    def wrapper(*args, **kwargs):
        timer = Time()
        timer.setStartTime()
        # 执行函数
        result = func(*args, **kwargs)
        timer.setEndTime()
        timer.printCostTime(func.__name__ + " cost_time 1")
        return result

    return wrapper


def get_ip_from_domain(domain):
    results = []
    ans = resolver.query(domain, "A")
    for i in ans.response.answer:
        for ip in i.items:
            results.append(str(ip))
    return results


def get_dict_md5(data):
    m_str = ""
    for each in sorted(data.keys()):
        m_str += each
        if isinstance(data[each], list):
            m_str += str(sorted(data[each]))
        else:
            m_str += str(data[each])
    return md5(m_str)


def get_cn_from_dn(dn):
    parts = dn.split(",")
    for each in parts:
        if each.lower().startswith("cn="):
            return each.split("=")[1]


def get_domain_from_dn(dn):
    domain_list = []
    parts = dn.split(",")
    for each in parts:
        if each.lower().startswith("dc="):
            domain_list.append(each.split("=")[1])
    return ".".join(domain_list)


def escape_ldap_filter(_str):
    _str = _str.replace("(", r"\28").replace(")", r"\29").replace("\\", r"\5c").replace("*", r"\2a").replace("/",
                                                                                                             r"\2f")
    return _str


if __name__ == '__main__':
    print(date_time_to_time(utc_to_datetime("2019-01-15T06:43:42.207Z")))
