#!/usr/bin/python
# -*- coding:utf-8 -*-
# Copyright 2019 Huawei Technologies Co.,Ltd.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.  You may obtain a copy of the
# License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.

import base64
import hashlib
import json
import re

from modules.huaweiapi.obs import const, progress

if const.IS_PYTHON2:
    import urllib
else:
    import urllib.parse as urllib
from modules.huaweiapi.obs.ilog import INFO, ERROR


def to_bool(item):
    try:
        return True if item is not None and str(item).lower() == 'true' else False
    except Exception:
        return None


def to_int(item):
    try:
        return int(item)
    except Exception:
        return None


def to_long(item):
    try:
        return const.LONG(item)
    except Exception:
        return None


def to_float(item):
    try:
        return float(item)
    except Exception:
        return None


def to_string(item):
    try:
        return str(item) if item is not None else ''
    except Exception:
        return ''


def is_valid(item):
    return item is not None and item.strip() != ''


class RequestFormat(object):

    @staticmethod
    def get_path_format():
        return PathFormat()

    @staticmethod
    def get_sub_domain_format():
        return SubdomainFormat()

    @classmethod
    def convert_path_string(cls, path_args, allowdNames=None):
        e = ''
        if isinstance(path_args, dict):
            e1 = '?'
            e2 = '&'
            for path_key, path_value in path_args.items():
                flag = True
                if allowdNames is not None and path_key not in allowdNames:
                    flag = False
                if flag:
                    path_key = encode_item(path_key, '/')
                    if path_value is None:
                        e1 += path_key + '&'
                        continue
                    e2 += path_key + '=' + encode_item(path_value, '/') + '&'
            e = (e1 + e2).replace('&&', '&').replace('?&', '?')[:-1]
        return e

    def get_endpoint(self, server, port, bucket):
        return

    def get_path_base(self, bucket, key):
        return

    def get_url(self, bucket, key, path_args):
        return


class PathFormat(RequestFormat):

    @staticmethod
    def get_server(server, bucket):
        return server

    def get_path_base(self, bucket, key):
        if bucket:
            return '/' + bucket + '/' + encode_object_key(key) if key else '/' + bucket
        return '/' + encode_object_key(key) if key else '/'

    def get_endpoint(self, server, port, bucket):
        if port == 80 or port == 443:
            return server
        return server + ':' + str(port)

    def get_url(self, bucket, key, path_args):
        path_base = self.get_path_base(bucket, key)
        path_arguments = self.convert_path_string(path_args)
        return path_base + path_arguments

    def get_full_url(self, is_secure, server, port, bucket, key, path_args):
        url = 'https://' if is_secure else 'http://'
        url += self.get_endpoint(server, port, bucket)
        url += self.get_url(bucket, key, path_args)
        return url


class SubdomainFormat(RequestFormat):

    @staticmethod
    def get_server(server, bucket):
        return bucket + '.' + server if bucket else server

    def get_path_base(self, bucket, key):
        if key is None:
            return '/'
        return '/' + encode_object_key(key)

    def get_endpoint(self, server, port, bucket):
        if port == 80 or port == 443:
            return self.get_server(server, bucket)
        return self.get_server(server, bucket) + ':' + str(port)

    def get_url(self, bucket, key, path_args):
        url = self.convert_path_string(path_args)
        return self.get_path_base(bucket, key) + url

    def get_full_url(self, is_secure, server, port, bucket, key, path_args):
        url = 'https://' if is_secure else 'http://'
        url += self.get_endpoint(server, port, bucket)
        url += self.get_url(bucket, key, path_args)
        return url


class delegate(object):
    def __init__(self, conn):
        self.conn = conn

    def send(self, data, final=False, stream_id=None):
        self.conn.send(data)


def conn_delegate(conn):
    return delegate(conn)


def get_readable_entity(readable, chunk_size=const.READ_ONCE_LENGTH, notifier=None, auto_close=True):
    if notifier is None:
        notifier = progress.NONE_NOTIFIER

    def entity(conn):
        try:
            while True:
                chunk = readable.read(chunk_size)
                if not chunk:
                    conn.send('0\r\n\r\n' if const.IS_PYTHON2 else '0\r\n\r\n'.encode('UTF-8'), final=True)
                    break
                newReadCount = len(chunk)
                if newReadCount > 0:
                    notifier.send(newReadCount)
                hex_chunk = hex(len(chunk))[2:]
                conn.send(hex_chunk if const.IS_PYTHON2 else hex_chunk.encode('UTF-8'))
                conn.send('\r\n' if const.IS_PYTHON2 else '\r\n'.encode('UTF-8'))
                conn.send(chunk)
                conn.send('\r\n' if const.IS_PYTHON2 else '\r\n'.encode('UTF-8'))
        finally:
            if hasattr(readable, 'close') and callable(readable.close) and auto_close:
                readable.close()

    return entity


def get_readable_entity_by_total_count(readable, totalCount, chunk_size=const.READ_ONCE_LENGTH, notifier=None,
                                       auto_close=True):
    return get_entity_for_send_with_total_count(readable, totalCount, chunk_size, notifier, auto_close)


def get_file_entity_by_total_count(file_path, totalCount, chunk_size=const.READ_ONCE_LENGTH, notifier=None):
    f = open(file_path, "rb")
    return get_entity_for_send_with_total_count(f, totalCount, chunk_size, notifier)


def get_entity_for_send_with_total_count(readable, totalCount=None, chunk_size=const.READ_ONCE_LENGTH, notifier=None,
                                         auto_close=True):
    if notifier is None:
        notifier = progress.NONE_NOTIFIER

    def entity(conn):
        readCount = 0
        try:
            while True:
                if totalCount is None or totalCount - readCount >= chunk_size:
                    readCountOnce = chunk_size
                else:
                    readCountOnce = totalCount - readCount
                chunk = readable.read(readCountOnce)
                newReadCount = len(chunk)
                if newReadCount > 0:
                    notifier.send(newReadCount)
                readCount += newReadCount
                if (totalCount is not None and readCount >= totalCount) or (totalCount is not None and not chunk):
                    conn.send(chunk, final=True)
                    break
                conn.send(chunk)
        finally:
            if hasattr(readable, 'close') and callable(readable.close) and auto_close:
                readable.close()

    return entity


def get_file_entity_by_offset_partsize(file_path, offset, totalCount, chunk_size=const.READ_ONCE_LENGTH, notifier=None):
    f = open(file_path, "rb")
    f.seek(offset)
    return get_entity_for_send_with_total_count(f, totalCount, chunk_size, notifier)


def is_ipaddress(item):
    return re.match(const.IPv4_REGEX, item)


def md5_encode(unencoded):
    m = hashlib.md5()
    unencoded = unencoded if const.IS_PYTHON2 else (
        unencoded.encode('UTF-8') if not isinstance(unencoded, bytes) else unencoded)
    m.update(unencoded)
    return m.digest()


def covert_string_to_bytes(str_object):
    if not const.IS_PYTHON2:
        if isinstance(str_object, str):
            return str_object.encode("UTF-8")
    return str_object


def base64_encode(unencoded):
    unencoded = unencoded if const.IS_PYTHON2 else (
        unencoded.encode('UTF-8') if not isinstance(unencoded, bytes) else unencoded)
    encode_str = base64.b64encode(unencoded, altchars=None)
    return encode_str if const.IS_PYTHON2 else encode_str.decode('UTF-8')


def encode_object_key(key):
    return encode_item(key, '/~')


def encode_item(item, safe='/'):
    return urllib.quote(to_string(item), safe)


def decode_item(item):
    return urllib.unquote(item)


def safe_trans_to_utf8(item):
    if not const.IS_PYTHON2:
        return item
    if item is not None:
        item = safe_encode(item)
        try:
            return item.decode('GB2312').encode('UTF-8')
        except Exception:
            return item
    return None


def safe_trans_to_gb2312(item):
    if not const.IS_PYTHON2:
        return item
    if item is not None:
        item = safe_encode(item)
        try:
            return item.decode('UTF-8').encode('GB2312')
        except Exception:
            return item
    return None


def safe_decode(item):
    if not const.IS_PYTHON2:
        return item
    if isinstance(item, str):
        try:
            item = item.decode('UTF-8')
        except Exception:
            try:
                item = item.decode('GB2312')
            except Exception:
                item = None
    return item


def safe_encode(item):
    if not const.IS_PYTHON2:
        return item
    if isinstance(item, const.UNICODE):
        try:
            item = item.encode('UTF-8')
        except UnicodeDecodeError:
            try:
                item = item.encode('GB2312')
            except Exception:
                item = None
    return item


def md5_file_encode_by_size_offset(file_path=None, size=None, offset=None, chuckSize=None):
    if file_path is not None and size is not None and offset is not None:
        m = hashlib.md5()
        with open(file_path, 'rb') as fp:
            CHUNK_SIZE = const.READ_ONCE_LENGTH if chuckSize is None else chuckSize
            fp.seek(offset)
            read_count = 0
            while read_count < size:
                read_size = CHUNK_SIZE if size - read_count >= CHUNK_SIZE else size - read_count
                data = fp.read(read_size)
                read_count_once = len(data)
                if read_count_once <= 0:
                    break
                m.update(data)
                read_count += read_count_once
        return m.digest()


def do_close(result, conn, connHolder, log_client=None):
    if not result:
        close_conn(conn, log_client)
    elif result.getheader('connection', '').lower() == 'close':
        if log_client:
            log_client.log(INFO, 'server inform to close connection')
        close_conn(conn, log_client)
    elif to_int(result.status) >= 500 or connHolder is None:
        close_conn(conn, log_client)
    elif hasattr(conn, '_clear') and conn._clear:
        close_conn(conn, log_client)
    else:
        if connHolder is not None:
            try:
                connHolder['connSet'].put_nowait(conn)
            except Exception:
                close_conn(conn, log_client)


def close_conn(conn, log_client=None):
    try:
        if conn:
            conn.close()
    except Exception as ex:
        if log_client:
            log_client.log(ERROR, ex)


SKIP_VERIFY_ATTR_TYPE = False


def verify_attr_type(value, allowedAttrType):
    if SKIP_VERIFY_ATTR_TYPE:
        return True
    if isinstance(allowedAttrType, list):
        for t in allowedAttrType:
            if isinstance(value, t):
                return True
        return False
    return isinstance(value, allowedAttrType)


def lazyCallback(*args, **kwargs):
    pass


def jsonLoadsForPy2(json_text):
    return _byteify(json.loads(json_text, object_hook=_byteify), ignore_dicts=True)


def _byteify(data, ignore_dicts=False):
    if isinstance(data, const.UNICODE):
        return data.encode('utf-8')
    if isinstance(data, list):
        return [_byteify(item, ignore_dicts=True) for item in data]
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    return data
