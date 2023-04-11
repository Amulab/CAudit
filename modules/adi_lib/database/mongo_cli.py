# coding=utf-8
import os

# import pymongo
# from bson import ObjectId
# from pymongo import DESCENDING

# from modules.adi_lib.common.log import logger
# from modules.adi_lib.common.util import Singleton

MONGO_CONFIG = {
    'host': os.getenv('MONGO_HOST', '10.133.35.103'),  # 主机
    'port': int(os.getenv('MONGO_PORT', 27017)),  # 端口
    'maxPoolSize': 1000,  # 最大连接池
    'socketTimeoutMS': None,
    'connectTimeoutMS': None,
    'authSource': os.getenv('MONGO_AUTH_SOURCE', 'admin'),  # 身份认证所用库
    'authMechanism': os.getenv('MONGO_AUTH_MECHANISM', 'SCRAM-SHA-1'),  # 认证机制
    'username': os.getenv('MONGO_USERNAME', "root"),  # 用于登录 MongoDB 服务的用户名
    'password': os.getenv('MONGO_PASSWORD', "root"),  # 用于登录 MongoDB 服务的用户密码
    'connect': False
}


# class Database(object):
#     """mongodb数据库的惰性封装：只在实际数据库操作时才去连接数据库"""
#     __metaclass__ = Singleton
#
#     __db__ = None
#
#     def __init__(self, mongo_config):
#         mongo_conf = {
#             'host': mongo_config["host"].split(":")[0],  # 主机
#             'port': int(mongo_config["host"].split(":")[1]),  # 端口
#             'maxPoolSize': 100,  # 最大连接池
#             'socketTimeoutMS': None,
#             'connectTimeoutMS': None,
#             'authSource': mongo_config["db_name"],  # 身份认证所用库
#             'authMechanism': 'SCRAM-SHA-1',  # 认证机制
#             'username': mongo_config["user"],  # 用于登录 MongoDB 服务的用户名
#             'password': mongo_config["password"],  # 用于登录 MongoDB 服务的用户密码
#             'connect': False
#         }
#         self.mongo_conf = mongo_conf
#         self.db_name = mongo_config["db_name"]
#
#     def __getattr__(self, name):
#         if not self.__db__:
#             self.__db__ = self.__connect()
#
#         return getattr(self.__db__, name)
#
#     def __getitem__(self, key):
#         if not self.__db__:
#             self.__db__ = self.__connect()
#
#         return self.__db__[key]
#
#     def __connect(self):
#         conn = pymongo.MongoClient(**self.mongo_conf)
#
#         return conn[self.db_name]
#
#     def get_mongo_db_instance(self):
#         if not self.__db__:
#             self.__db__ = self.__connect()
#         return self.__db__


# class Collection(object):
#     __metaclass__ = Singleton
#
#     table = 'mongo_obj'
#
#     def __init__(self, mongo_conf):
#         self.db = Database(mongo_conf)
#         self.coll = self.db[self.table]
#
#     def find(self):
#         raise NotImplementedError('not implemented')
#
#     def __getattr__(self, attr):
#         """deal with method missing as a delegator"""
#         return getattr(self.coll, attr)
#
#     def count(self, cond):
#         """
#         统计数量
#         :param col_name: collection name
#         :param cond: condition or filter
#         """
#         col = self.coll
#         return col.count(cond)
#
#     def get_list_by_condition_name(self,
#                                    collection_name,
#                                    cond,
#                                    filter_out_key={"_id": 0},
#                                    sort_key=None,
#                                    sort_direction=DESCENDING,
#                                    skip=0,
#                                    limit=100,
#                                    **kwargs):
#         """mongodb find()函数封装，获取集合里面的信息
#         :param collection_name: collection name
#         :param cond: condition or filter
#         :param sort_key: key to sort
#         :param sort_direction: sort direction
#         :param skip: skip number
#         :param limit: limit number
#         """
#         if sort_key is None:
#             sort_key = '_i'
#         col = self.db[collection_name]
#         data = []
#         for item in col.find(cond, filter_out_key).sort(
#                 sort_key, sort_direction).skip(skip).limit(limit):
#             data.append(item)
#         return data
#
#     def get_count_by_condition(self, collection_name, cond):
#         """查询集合的数据数量
#         :param col_name: collection name
#         :param cond: condition or filter
#         """
#         col = self.db[collection_name]
#         return col.count(cond)
#
#     def get_list(self, collection_name, cond, sort_key=None,
#                  filter_out_key={"_id": 0},
#                  sort_direction=DESCENDING,
#                  skip=0,
#                  limit=100,
#                  **kwargs):
#         """mongodb find()函数封装，获取集合里面的信息
#
#         :param collection_name: collection_name
#         :param cond: condition or filter
#         :param sort_key: key to sort
#         :param sort_direction: sort direction
#         :param skip: skip number
#         :param limit: limit number
#         """
#         if sort_key is None:
#             sort_key = '_i'
#         data = []
#         data.extend(
#             self.db[collection_name].find(cond, filter_out_key).sort(
#                 sort_key, sort_direction).skip(skip).limit(limit))
#         return data
#
#     def find_by_ids(self, id_list):
#         try:
#             return self.coll.find({"_id": {"$in": list(id_list)}})
#         except Exception as e:
#             logger.exception(str(e))
#             raise
#
#     def update(self, cond, values, **kwargs):
#         """
#         根据指定条件更新数据
#         :param cond: condition or filter
#         :param values: values to update
#         """
#         self.coll.update(cond, {'$set': values}, **kwargs)
#
#     def update_one(self, id, values, **kwargs):
#         """
#         根据Object_id 更新一条记录
#         :param id: _id
#         :param values: values to update
#         """
#         _id = ObjectId(id)
#         self.coll.find_one_and_update({'_id': _id}, {'$set': values})
