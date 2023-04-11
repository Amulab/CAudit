# coding=utf-8

# from redis import StrictRedis
# from redis import ConnectionPool
#
# from modules.adi_lib.common.util import Singleton
#
#
# class RedisClient(object):
#     __metaclass__ = Singleton
#
#     def __init__(self, redis_conf):
#         redis_uri = redis_conf["uri"]
#         redis_pool = ConnectionPool.from_url(redis_uri, decode_responses=False, max_connections=20, socket_timeout=5)
#         self.conn = StrictRedis(connection_pool=redis_pool)
