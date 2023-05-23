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

from __future__ import print_function

import functools
import math
import os
import random
import re
import threading
import time
import traceback
import json
from inspect import isfunction
from modules.huaweiapi.obs import auth, const, convertor, loadtoken, locks, progress, util
from modules.huaweiapi.obs.bucket import BucketClient
from modules.huaweiapi.obs.cache import LocalCache
from modules.huaweiapi.obs.extension import _download_files
from modules.huaweiapi.obs.ilog import DEBUG, ERROR, INFO, LogClient, NoneLogClient, WARNING
from modules.huaweiapi.obs.model import ACL, AppendObjectContent, AppendObjectHeader, BaseModel, CopyObjectHeader, CreateBucketHeader, \
    FetchPolicy, GetObjectHeader, GetObjectRequest, GetResult, ListMultipartUploadsRequest, Logging, Notification, \
    ObjectStream, PutObjectHeader, ResponseWrapper, SetObjectMetadataHeader, Versions, _FetchJob, ExtensionHeader, \
    BucketAliasModel, Replication, ReplicationRule
from modules.huaweiapi.obs.transfer import _resume_download, _resume_upload

if const.IS_PYTHON2:
    from urlparse import urlparse
    import httplib
else:
    import http.client as httplib
    from urllib.parse import urlparse


class _RedirectException(Exception):
    def __init__(self, msg, location, result=None):
        self.msg = msg
        self.location = location
        self.result = result

    def __str__(self):
        return self.msg


class _InternalException(Exception):
    def __init__(self, result):
        self.result = result


class _SecurityProvider(object):
    def __init__(self, access_key_id, secret_access_key, security_token=None):
        access_key_id = util.to_string(util.safe_encode(access_key_id)).strip()
        secret_access_key = util.to_string(util.safe_encode(secret_access_key)).strip()
        security_token = util.to_string(
            util.safe_encode(security_token)).strip() if security_token is not None else None
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.security_token = security_token


def _getCacheKey(name, obsClient, *args, **kwargs):
    key = ''
    list_operation = ['listBuckets', 'listBucketAlias']
    if name == 'copyObject':
        if kwargs.get('destBucketName'):
            key = kwargs['destBucketName']
        elif len(args) >= 4:
            key = args[3]

        if not obsClient.is_cname:
            obsClient._assert_not_null(key, 'destBucketName is empty')

    elif name not in list_operation:
        if len(args) > 1:
            key = args[1]
        elif kwargs.get('bucketName'):
            key = kwargs['bucketName']

        if not obsClient.is_cname:
            obsClient._assert_not_null(key, 'bucketName is empty')
    return key


def _wrapperFinally(obsClient, name, start):
    if obsClient:
        obsClient.log_client.log(INFO, '%s cost %s ms' % (name, int((time.time() - start) * 1000)))
        if obsClient.is_signature_negotiation and hasattr(obsClient.thread_local, 'signature'):
            del obsClient.thread_local.signature


def _getObsClient(*args):
    obsClient = args[0] if isinstance(args[0], ObsClient) else None
    return obsClient


def _isCreateBucket(obsClient, name, key):
    return obsClient._getApiVersion() if name == 'createBucket' else obsClient._getApiVersion(key)


def _is_signature_negotiation(obsClient, name, key):
    caches = obsClient.cache
    if name == 'listBuckets':
        authType, resp = obsClient._getApiVersion()
        if not authType:
            return authType, resp
        obsClient.thread_local.signature = authType
        return authType, resp
    else:
        result_dic = caches.get(key)
        if not result_dic:
            with locks.get_lock(hash(key) % locks.LOCK_COUNT):
                result_dic = caches.get(key)
                if not result_dic:
                    authType, resp = _isCreateBucket(obsClient, name, key)
                    if not authType:
                        return authType, resp
                    result_dic = {'signature': authType, 'expire': random.randint(900, 1200) + caches.nowTime()}
                    if name != 'createBucket':
                        caches.set(key, result_dic)
        obsClient.thread_local.signature = result_dic['signature']
        return True, ""


def funcCache(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        ret = None
        obsClient = _getObsClient(*args)
        try:
            if obsClient:
                obsClient.log_client.log(INFO, 'enter %s ...' % func.__name__)
                key = _getCacheKey(func.__name__, obsClient, *args, **kwargs)

                if obsClient.is_signature_negotiation:
                    black_list = ['listAvailableZoneInfo', 'createVirtualBucket', 'createBucketAlias',
                                  'listBucketAlias', 'deleteBucketAlias']
                    if func.__name__ in black_list:
                        obsClient.thread_local.signature = const.OBS_SIGNATURE
                    else:
                        authType, resp = _is_signature_negotiation(obsClient, func.__name__, key)
                        if not authType:
                            return resp
            ret = func(*args, **kwargs)
        except Exception as e:
            if obsClient and obsClient.log_client:
                obsClient.log_client.log(INFO, traceback.format_exc())
            raise e
        finally:
            _wrapperFinally(obsClient, func.__name__, start)
        return ret

    return wrapper


class HaWrapper(object):
    def __init__(self, thread_local, signature):
        self.obsHA = convertor.Adapter('obs')
        self.v2HA = convertor.Adapter('v2')
        self.v4HA = convertor.Adapter('v4')
        self.thread_local = thread_local
        self.signature = signature

    def __getattr__(self, item):
        signature = self.thread_local.signature if hasattr(self.thread_local, 'signature') else self.signature
        ha = self.obsHA if signature == 'obs' else self.v4HA if signature == 'v4' else self.v2HA
        return getattr(ha, item)


class ConvertWrapper(object):
    def __init__(self, thread_local, signature):
        self.obsCover = convertor.Convertor('obs', convertor.Adapter('obs'))
        self.v2Cover = convertor.Convertor('v2', convertor.Adapter('v2'))
        self.v4Cover = convertor.Convertor('v4', convertor.Adapter('v4'))
        self.thread_local = thread_local
        self.signature = signature

    def __getattr__(self, item):
        signature = self.thread_local.signature if hasattr(self.thread_local, 'signature') else self.signature
        convert = self.obsCover if signature == 'obs' else self.v4Cover if signature == 'v4' else self.v2Cover
        return getattr(convert, item)


class _BasicClient(object):
    def __init__(self, access_key_id='', secret_access_key='', is_secure=True, server=None,
                 signature='obs', region='region', path_style=False, ssl_verify=False,
                 port=None, max_retry_count=3, timeout=60, chunk_size=const.READ_ONCE_LENGTH,
                 long_conn_mode=False, proxy_host=None, proxy_port=None,
                 proxy_username=None, proxy_password=None, security_token=None,
                 custom_ciphers=None, use_http2=False, is_signature_negotiation=True, is_cname=False,
                 max_redirect_count=10, security_providers=None, security_provider_policy=None, client_mode='obs'):
        self.securityProvider = _SecurityProvider(access_key_id, secret_access_key, security_token)
        server = server if server is not None else ''
        server = util.to_string(util.safe_encode(server))

        _server = urlparse(server)

        hostname = self._parse_server_hostname(_server)
        is_secure = self._check_server_secure(_server, is_secure)
        host_port, port = self._split_host_port(hostname, port)
        self.security_provider_policy = security_provider_policy
        self._parse_security_providers(security_providers)

        self.is_secure = is_secure
        self.server = host_port[0]

        path_style = self._check_path_style(path_style)
        self.signature = util.to_string(util.safe_encode(signature))
        self.region = region
        self.path_style = path_style
        self.ssl_verify = ssl_verify
        self.calling_format = self._parse_calling_format()
        self.port = self._parse_port(port, is_secure)

        self.max_retry_count = max_retry_count
        self.timeout = timeout
        self.chunk_size = chunk_size
        self.log_client = NoneLogClient()
        self.use_http2 = use_http2
        self.is_signature_negotiation = is_signature_negotiation
        self.is_cname = is_cname
        self.max_redirect_count = max_redirect_count

        if client_mode == 'obs':
            if self.path_style or self.is_cname:
                self.is_signature_negotiation = False
                if self.signature == 'obs':
                    self.signature = 'v2'
        elif client_mode == 'workflow':
            self.is_signature_negotiation = False

        self.context = None
        if self.is_secure:
            if self.use_http2:
                from modules.huaweiapi.obs import http2
                self.context = http2._get_ssl_context(self.ssl_verify)
            else:
                self._init_ssl_context(custom_ciphers)

        self.long_conn_mode = long_conn_mode

        self.connHolder = None
        if self.long_conn_mode:
            self._init_connHolder()

        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.pattern = re.compile('xmlns="http.*?"')
        self.thread_local = threading.local()
        self.thread_local.signature = self.signature
        if self.is_signature_negotiation:
            self.cache = LocalCache(maxlen=100)
            self.ha = HaWrapper(self.thread_local, self.signature)
            self.convertor = ConvertWrapper(self.thread_local, self.signature)
        else:
            self.ha = convertor.Adapter(self.signature)
            self.convertor = convertor.Convertor(self.signature, self.ha)
        self.json_response_method_name = 'GetJsonResponse'

    @staticmethod
    def _parse_server_hostname(server):
        hostname = server.netloc if util.is_valid(server.netloc) else server.path
        if not util.is_valid(hostname):
            raise Exception('server is not set correctly')
        return hostname

    @staticmethod
    def _check_server_secure(server, is_secure):
        if util.is_valid(server.scheme):
            if server.scheme == 'https':
                is_secure = True
            elif server.scheme == 'http':
                is_secure = False
        return is_secure

    def _parse_security_providers(self, security_providers):
        if security_providers is None:
            self.security_providers = [loadtoken.ENV, loadtoken.ECS]
        else:
            self.security_providers = security_providers
        try:
            if security_providers == []:
                raise ValueError('no available security_providers')
            for method in self.security_providers:
                getattr(method, '__name__')
                if not isfunction(method.search):
                    raise AttributeError(method + 'has no function called search')
        except Exception:
            self.security_provider_policy = None
            print(traceback.format_exc())

    @staticmethod
    def _split_host_port(hostname, port):
        host_port = hostname.split(':')
        if len(host_port) == 2:
            port = util.to_int(host_port[1])
        return host_port, port

    def _check_path_style(self, path_style):
        return True if util.is_ipaddress(self.server) else path_style

    @staticmethod
    def _parse_port(port, is_secure):
        if port is None:
            if is_secure:
                port = const.DEFAULT_SECURE_PORT
            else:
                port = const.DEFAULT_INSECURE_PORT
        return port

    def _parse_calling_format(self):
        if self.path_style:
            return util.RequestFormat.get_path_format()
        else:
            return util.RequestFormat.get_sub_domain_format()

    def _get_token(self):
        from modules.huaweiapi.obs.searchmethod import get_token
        try:
            if self.security_provider_policy is not None:
                if self.securityProvider.access_key_id != '' and self.securityProvider.secret_access_key != '':
                    return self.securityProvider

                value_dict = get_token(self.security_providers, name=self.security_provider_policy)
                securityProvider = _SecurityProvider(value_dict.get('accessKey'), value_dict.get('secretKey'),
                                                     value_dict.get('securityToken'))
                return securityProvider
        except Exception:
            self.log_client.log(WARNING, traceback.format_exc())
        return self.securityProvider

    def _init_connHolder(self):
        if const.IS_PYTHON2:
            from Queue import Queue
        else:
            from queue import Queue
        self.connHolder = {'connSet': Queue(), 'lock': threading.Lock()}

    def _init_ssl_context(self, custom_ciphers):
        try:
            import ssl
            if hasattr(ssl, 'SSLContext'):
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context.options |= ssl.OP_NO_SSLv2
                context.options |= ssl.OP_NO_SSLv3
                if custom_ciphers is not None:
                    custom_ciphers = util.to_string(custom_ciphers).strip()
                    if custom_ciphers != '' and hasattr(context, 'set_ciphers') and callable(context.set_ciphers):
                        context.set_ciphers(custom_ciphers)
                if self.ssl_verify:
                    import _ssl
                    cafile = util.to_string(self.ssl_verify)
                    context.options |= getattr(_ssl, "OP_NO_COMPRESSION", 0)
                    context.verify_mode = ssl.CERT_REQUIRED
                    if os.path.isfile(cafile):
                        context.load_verify_locations(cafile)
                else:
                    context.verify_mode = ssl.CERT_NONE
                if hasattr(context, 'check_hostname'):
                    context.check_hostname = False
                self.context = context
        except Exception:
            print(traceback.format_exc())

    def close(self):
        if self.connHolder is not None:
            with self.connHolder['lock']:
                while not self.connHolder['connSet'].empty():
                    conn = self.connHolder['connSet'].get()
                    if conn and hasattr(conn, 'close'):
                        try:
                            conn.close()
                        except Exception as ex:
                            self.log_client.log(WARNING, ex)
        self.connHolder = None
        if self.log_client:
            self.log_client.close()

    def refresh(self, access_key_id, secret_access_key, security_token=None):
        self.securityProvider = _SecurityProvider(access_key_id, secret_access_key, security_token)

    def initLog(self, log_config=None, log_name='OBS_LOGGER'):
        if log_config:
            self.log_client = LogClient(log_config, 'OBS_LOGGER' if const.IS_WINDOWS else log_name, log_name)
            msg = ['[OBS SDK Version=' + const.OBS_SDK_VERSION]
            msg.append('Endpoint=' + ('%s://%s:%d' % ('https' if self.is_secure else 'http', self.server, self.port)))
            msg.append('Access Mode=' + ('Path' if self.path_style else 'Virtual Hosting') + ']')
            self.log_client.log(WARNING, '];['.join(msg))

    @staticmethod
    def _assert_not_null(param, msg):
        param = util.safe_encode(param)
        if param is None or util.to_string(param).strip() == '':
            raise Exception(msg)

    def _generate_object_url(self, ret, bucketName, objectKey):
        if ret and ret.status < 300 and ret.body:
            ret.body.objectUrl = self.calling_format.get_full_url(self.is_secure, self.server, self.port, bucketName,
                                                                  objectKey, {})

    def _make_options_request(self, bucketName, objectKey=None, pathArgs=None, headers=None, methodName=None,
                              extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_OPTIONS, bucketName, objectKey, pathArgs, headers,
                                             methodName=methodName, extensionHeaders=extensionHeaders)

    def _make_head_request(self, bucketName, objectKey=None, pathArgs=None, headers=None, methodName=None,
                           skipAuthentication=False, extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_HEAD, bucketName, objectKey, pathArgs, headers,
                                             methodName=methodName, skipAuthentication=skipAuthentication,
                                             extensionHeaders=extensionHeaders)

    def _make_get_request(self, bucketName='', objectKey=None, pathArgs=None, headers=None, methodName=None,
                          parseMethod=None, readable=False, extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_GET, bucketName, objectKey, pathArgs, headers,
                                             methodName=methodName, parseMethod=parseMethod, readable=readable,
                                             extensionHeaders=extensionHeaders)

    def _make_delete_request(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None,
                             methodName=None, extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_DELETE, bucketName, objectKey, pathArgs, headers, entity,
                                             methodName=methodName, extensionHeaders=extensionHeaders)

    def _make_post_request(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None,
                           chunkedMode=False, methodName=None, readable=False, extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_POST, bucketName, objectKey, pathArgs, headers, entity,
                                             chunkedMode, methodName=methodName, readable=readable,
                                             extensionHeaders=extensionHeaders)

    def _make_put_request(self, bucketName, objectKey=None, pathArgs=None, headers=None, entity=None, chunkedMode=False,
                          methodName=None, readable=False, extensionHeaders=None):
        return self._make_request_with_retry(const.HTTP_METHOD_PUT, bucketName, objectKey, pathArgs, headers, entity,
                                             chunkedMode, methodName=methodName, readable=readable,
                                             extensionHeaders=extensionHeaders)

    def _make_error_result(self, e, ret):
        self.log_client.log(ERROR, 'request error, %s' % e)
        self.log_client.log(ERROR, traceback.format_exc())
        if ret is not None:
            return ret
        raise e

    def _make_request_with_retry(self, methodType, bucketName, objectKey=None, pathArgs=None, headers=None,
                                 entity=None, chunkedMode=False, methodName=None, readable=False, parseMethod=None,
                                 redirectLocation=None, skipAuthentication=False, extensionHeaders=None):
        flag = 0
        redirect_count = 0
        conn = None
        _redirectLocation = redirectLocation
        redirectFlag = False
        while True:
            try:
                conn = self._make_request_internal(methodType, bucketName, objectKey, pathArgs, headers, entity,
                                                   chunkedMode, _redirectLocation,
                                                   skipAuthentication=skipAuthentication, redirectFlag=redirectFlag,
                                                   extensionHeaders=extensionHeaders)
                return self._parse_xml(conn, methodName, readable) if not parseMethod else parseMethod(conn)
            except Exception as e:
                ret = None

                if isinstance(e, _InternalException):
                    ret = e.result
                else:
                    util.close_conn(conn, self.log_client)
                    if isinstance(e, _RedirectException):
                        redirect_count += 1
                        _redirectLocation = e.location
                        flag -= 1
                        ret = e.result
                        if methodType == const.HTTP_METHOD_GET and e.result.status == 302:
                            redirectFlag = True
                if redirect_count >= self.max_redirect_count:
                    self.log_client.log(ERROR, 'request redirect count [%d] greater than max redirect count [%d]' % (
                        redirect_count, self.max_redirect_count))
                    return self._make_error_result(e, ret)
                if flag >= self.max_retry_count or readable:
                    return self._make_error_result(e, ret)
                flag += 1
                time.sleep(math.pow(2, flag) * 0.05)
                self.log_client.log(WARNING, 'request again, time:%d' % int(flag))
                continue

    def _make_request_internal(self, method, bucketName='', objectKey=None, pathArgs=None, headers=None, entity=None,
                               chunkedMode=False, redirectLocation=None, skipAuthentication=False, redirectFlag=False,
                               extensionHeaders=None):
        objectKey = util.safe_encode(objectKey)
        if objectKey is None:
            objectKey = ''
        port = None
        scheme = None
        path = None
        if redirectLocation:
            redirectLocation = urlparse(redirectLocation)
            connect_server = redirectLocation.hostname
            scheme = redirectLocation.scheme
            port = self._parse_port(redirectLocation.port, scheme.lower() == 'https')
            redirect = True
            _path = redirectLocation.path
            query = redirectLocation.query
            path = _path + '?' + query if query else _path
            skipAuthentication = True
            if not redirectFlag:
                skipAuthentication = False

        else:
            connect_server = self.server if self.is_cname else self.calling_format.get_server(self.server, bucketName)
            redirect = False
            port = self.port

        if self.is_cname:
            bucketName = ''

        if not path:
            path = self.calling_format.get_url(bucketName, objectKey, pathArgs)

        extension_headers = self.convertor.trans_get_extension_headers(extensionHeaders)
        headers = self._parse_extension_headers(headers, extension_headers)
        headers = self._rename_request_headers(headers, method)

        entity, headers = self._parse_entity(entity, headers)

        headers[const.HOST_HEADER] = '%s:%s' % (connect_server, port) if port not in (443, 80) else connect_server
        header_config = self._add_auth_headers(headers, method, bucketName, objectKey, pathArgs, skipAuthentication)

        header_log = header_config.copy()
        header_log[const.HOST_HEADER] = '******'
        header_log[const.AUTHORIZATION_HEADER] = '******'
        if self.ha.security_token_header() in header_log:
            header_log[self.ha.security_token_header()] = "******"
        self.log_client.log(DEBUG, 'method:%s, path:%s, header:%s', method, path, header_log)
        conn = self._send_request(connect_server, method, path, header_config, entity, port, scheme, redirect,
                                  chunkedMode)
        return conn

    @staticmethod
    def _parse_extension_headers(headers, extension_headers):
        if len(extension_headers) > 0:
            if headers is None or not isinstance(headers, dict):
                headers = {}
            else:
                headers = headers.copy()
            for key, value in extension_headers.items():
                headers[key] = value
        return headers

    @staticmethod
    def _parse_entity(entity, headers):
        if entity is not None and not callable(entity):
            entity = util.safe_encode(entity)
            if not isinstance(entity, str) and not isinstance(entity, bytes):
                entity = util.to_string(entity)
            if not const.IS_PYTHON2:
                entity = entity.encode('UTF-8') if not isinstance(entity, bytes) else entity
            headers[const.CONTENT_LENGTH_HEADER] = util.to_string(len(entity))
        return entity, headers

    def _add_auth_headers(self, headers, method, bucketName, objectKey, pathArgs, skipAuthentication=False):
        from datetime import datetime

        now_date = None
        if self.ha.date_header() not in headers:
            now_date = datetime.utcnow()
            headers[const.DATE_HEADER] = now_date.strftime(const.GMT_DATE_FORMAT)

        if skipAuthentication:
            return headers

        securityProvider = self._get_token()
        ak = securityProvider.access_key_id
        sk = securityProvider.secret_access_key

        if util.is_valid(ak) and util.is_valid(sk):
            if securityProvider.security_token is not None:
                headers[self.ha.security_token_header()] = securityProvider.security_token

            cur_signature = self.thread_local.signature.lower() if self.is_signature_negotiation else \
                self.signature.lower()
            if cur_signature == 'v4':
                if now_date is None:
                    now_date = datetime.strptime(headers[self.ha.date_header()], const.LONG_DATE_FORMAT)
                shortDate = now_date.strftime(const.SHORT_DATE_FORMAT)
                longDate = now_date.strftime(const.LONG_DATE_FORMAT)
                v4Auth = auth.V4Authentication(ak, sk, str(self.region) if self.region is not None else '', shortDate,
                                               longDate, self.path_style, self.ha)
                ret = v4Auth.doAuth(method, bucketName, objectKey, pathArgs, headers)

                log_canonical_request = ret[const.CANONICAL_REQUEST]
                if self.ha.security_token_header() in headers:
                    log_canonical_request = str.replace(log_canonical_request, headers[self.ha.security_token_header()],
                                                        "******")
                self.log_client.log(DEBUG, '%s: %s' % (const.CANONICAL_REQUEST, log_canonical_request))
            else:
                obsAuth = auth.Authentication(ak, sk, self.path_style, self.ha, self.server, self.is_cname)
                ret = obsAuth.doAuth(method, bucketName, objectKey, pathArgs, headers)
                log_canonical_string = ret[const.CANONICAL_STRING]
                if self.ha.security_token_header() in headers:
                    log_canonical_string = str.replace(log_canonical_string, headers[self.ha.security_token_header()],
                                                       "******")
                self.log_client.log(DEBUG, '%s: %s' % (const.CANONICAL_STRING, log_canonical_string))
            headers[const.AUTHORIZATION_HEADER] = ret[const.AUTHORIZATION_HEADER]
        return headers

    def _rename_request_headers(self, headers, method):
        new_headers = {}
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k is not None and v is not None:
                    k = util.to_string(k).strip()
                    if k.lower() not in const.ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES and not k.lower().startswith(
                            const.V2_HEADER_PREFIX) and not k.lower().startswith(const.OBS_HEADER_PREFIX):
                        if method not in (const.HTTP_METHOD_PUT, const.HTTP_METHOD_POST):
                            continue
                        k = self.ha._get_meta_header_prefix() + k

                    if k.lower().startswith(self.ha._get_meta_header_prefix()):
                        k = util.encode_item(k, ' ;/?:@&=+$,')

                    new_headers = self._rename_request_headers_handle(k, v, new_headers)
        return new_headers

    def _rename_request_headers_handle(self, k, v, new_headers):
        if k.lower() == self.ha._get_header_prefix() + 'copy-source':
            index = v.rfind('?versionId=')
            if index > 0:
                new_headers[k] = util.encode_item(v[0:index], '/') + v[index:]
            else:
                new_headers[k] = util.encode_item(v, '/')
        else:
            new_headers[k] = v if (isinstance(v, list)) else util.encode_item(v, ' ;/?:@&=+$,\'*')
        return new_headers

    def _get_server_connection(self, server, port=None, scheme=None, redirect=False, proxy_host=None, proxy_port=None):

        is_secure = self.is_secure if scheme is None else True if scheme == 'https' else False

        if self.connHolder is not None and not self.connHolder['connSet'].empty() and not redirect:
            try:
                return self.connHolder['connSet'].get_nowait()
            except Exception:
                self.log_client.log(DEBUG, 'can not get conn, will create a new one')

        if self.use_http2:
            from modules.huaweiapi.obs import http2
            conn = http2._get_server_connection(server, port, self.context, is_secure, proxy_host, proxy_port)
        else:
            conn = self._get_server_connection_use_http1x(is_secure, server, port, proxy_host, proxy_port)

        if redirect:
            conn._clear = True

        return conn

    def _get_server_connection_use_http1x(self, is_secure, server, port, proxy_host, proxy_port):
        if proxy_host is not None and proxy_port is not None:
            server = proxy_host
            port = proxy_port

        if is_secure:
            if const.IS_PYTHON2:
                try:
                    conn = httplib.HTTPSConnection(server, port=port, timeout=self.timeout, context=self.context)
                except Exception:
                    conn = httplib.HTTPSConnection(server, port=port, timeout=self.timeout)
            else:
                conn = httplib.HTTPSConnection(server, port=port, timeout=self.timeout, context=self.context,
                                               check_hostname=None)
        else:
            conn = httplib.HTTPConnection(server, port=port, timeout=self.timeout)

        return conn

    def _send_request(self, server, method, path, header, entity=None, port=None, scheme=None, redirect=False,
                      chunkedMode=False):
        conn = None
        header = header or {}
        connection_key = const.CONNECTION_HEADER
        conn, header = self._parse_request_connection(server, port, scheme, connection_key, redirect, header)

        header[const.USER_AGENT_HEADER] = 'obs-sdk-python/' + const.OBS_SDK_VERSION

        if method == const.HTTP_METHOD_OPTIONS and not self.use_http2:
            conn.putrequest(method, path, skip_host=1)
            for k, v in header.items():
                if isinstance(v, list):
                    for item in v:
                        conn.putheader(k, item)
                else:
                    conn.putheader(k, v)
            conn.endheaders()
        else:
            if chunkedMode:
                header[const.TRANSFER_ENCODING_HEADER] = const.TRANSFER_ENCODING_VALUE

            if self.use_http2:
                conn.request(method, path, body=entity, headers=header)
            else:
                self._parse_connection_chunked_mode(conn, chunkedMode, method, path, header)
                if entity is not None:
                    if callable(entity):
                        entity(util.conn_delegate(conn))
                    else:
                        conn.send(entity)
                        self.log_client.log(DEBUG, 'request content:%s', util.to_string(entity))
        return conn

    def _parse_request_connection(self, server, port, scheme, connection_key, redirect, header):
        if self.proxy_host is not None and self.proxy_port is not None:
            conn = self._get_server_connection(server, port, scheme, redirect, util.to_string(self.proxy_host),
                                               util.to_int(self.proxy_port))
            _header = {}
            if self.proxy_username is not None and self.proxy_password is not None:
                _header[const.PROXY_AUTHORIZATION_HEADER] = 'Basic ' \
                                                            '%s' % (
                                                                util.base64_encode(util.to_string(
                                                                    self.proxy_username) + ':' + util.to_string(
                                                                    self.proxy_password))
                                                            )
            if not self.use_http2:
                conn.set_tunnel(server, port, _header)
            else:
                header[const.PROXY_AUTHORIZATION_HEADER] = _header[const.PROXY_AUTHORIZATION_HEADER]
            connection_key = const.PROXY_CONNECTION_HEADER
        else:
            conn = self._get_server_connection(server, port, scheme, redirect)
        if self.long_conn_mode:
            header[connection_key] = const.CONNECTION_KEEP_ALIVE_VALUE
        else:
            header[const.CONNECTION_HEADER] = const.CONNECTION_CLOSE_VALUE
        return conn, header

    @staticmethod
    def _parse_connection_chunked_mode(conn, chunkedMode, method, path, header):
        if chunkedMode:
            conn.putrequest(method, path, skip_host=1)
            for k, v in header.items():
                conn.putheader(k, v)
            conn.endheaders()
        else:
            conn.request(method, path, headers=header)

    def _getNoneResult(self, message='None Result'):
        raise Exception(message)

    def _parse_xml(self, conn, methodName=None, readable=False):
        if not conn:
            return self._getNoneResult('connection is none')
        result = None
        try:
            result = conn.getresponse(True) if const.IS_PYTHON2 else conn.getresponse()
            if not result:
                return self._getNoneResult('response is none')
            return self._parse_xml_internal(result, methodName, readable=readable)
        except _RedirectException as ex:
            raise ex
        except _InternalException as ex:
            raise ex
        except Exception as e:
            conn._clear = True
            self.log_client.log(ERROR, traceback.format_exc())
            raise e
        finally:
            util.do_close(result, conn, self.connHolder, self.log_client)

    def _parse_content(self, objectKey, conn, response, download_start='',
                       downloadPath=None, chuckSize=const.READ_ONCE_LENGTH, loadStreamInMemory=False,
                       progressCallback=None, notifier=None):
        if not conn:
            return self._getNoneResult('connection is none')
        close_conn_flag = True
        result_wrapper = None
        try:
            if not response:
                return self._getNoneResult('response is none')

            if not util.to_int(response.status) < 300:
                return self._parse_xml_internal(response)

            headers = {}
            for k, v in response.getheaders():
                headers[k.lower()] = v

            content_length = headers.get('content-length')
            content_length = util.to_long(content_length) if content_length is not None else None
            if not notifier:
                notifier = self._get_notifier(content_length, progressCallback)
                notifier.start()
            result_wrapper = ResponseWrapper(conn, response, self.connHolder, content_length, notifier)
            if loadStreamInMemory:
                self.log_client.log(DEBUG, 'loadStreamInMemory is True, read stream into memory')
                buf = self._get_buffer_data(result_wrapper, chuckSize)
                body = ObjectStream(buffer=buf, size=util.to_long(len(buf)) if buf is not None else 0)
            elif downloadPath is None:
                self.log_client.log(DEBUG, 'DownloadPath is none, return conn directly')
                close_conn_flag = False
                body = ObjectStream(response=result_wrapper)
            else:
                downloadPath = util.safe_encode(downloadPath)
                file_path, _ = self._get_data(result_wrapper, downloadPath, chuckSize)
                body = ObjectStream(url=util.to_string(file_path))
                self.log_client.log(DEBUG, 'DownloadPath is ' + util.to_string(file_path))

            status = util.to_int(response.status)
            reason = response.reason
            self.convertor.parseGetObject(headers, body)
            header = self._rename_response_headers(headers)
            requestId = dict(header).get('request-id')
            return GetResult(status=status, reason=reason, header=header, body=body, requestId=requestId)
        except _RedirectException as ex:
            raise ex
        except Exception as e:
            self.log_client.log(ERROR, traceback.format_exc())
            raise e
        finally:
            if close_conn_flag:
                if result_wrapper is not None:
                    result_wrapper.close()
                else:
                    util.do_close(response, conn, self.connHolder, self.log_client)

    @staticmethod
    def _get_buffer_data(resultWrapper, chuckSize):
        buf = None
        appendList = []
        while True:
            chunk = resultWrapper.read(chuckSize)
            if not chunk:
                if bool(appendList):
                    tempStr = ""
                    if not const.IS_PYTHON2:
                        tempStr = b""
                    buf = tempStr.join(appendList)
                    del appendList[:]
                break
            appendList.append(chunk)
        return buf

    @staticmethod
    def _get_notifier(content_length, progressCallback):
        return progress.ProgressNotifier(progressCallback,
                                         content_length) if content_length is not None and content_length > 0 \
                                                            and progressCallback is not None else progress.NONE_NOTIFIER

    @staticmethod
    def _get_data(resultWrapper, downloadPath, chuckSize):
        origin_file_path = downloadPath
        read_count = 0
        if const.IS_WINDOWS:
            downloadPath = util.safe_trans_to_gb2312(downloadPath)
        pathDir = os.path.dirname(downloadPath)
        if not os.path.exists(pathDir):
            os.makedirs(pathDir, 0o755)
        with open(downloadPath, 'wb') as f:
            while True:
                chunk = resultWrapper.read(chuckSize)
                if not chunk:
                    break
                f.write(chunk)
                read_count += len(chunk)
        return origin_file_path, read_count

    @staticmethod
    def _rename_key(k, v):
        flag = 0
        if k.startswith(const.V2_META_HEADER_PREFIX):
            k = k[k.index(const.V2_META_HEADER_PREFIX) + len(const.V2_META_HEADER_PREFIX):]
            k = util.decode_item(k)
            v = util.decode_item(v)
            flag = 1
        elif k.startswith(const.V2_HEADER_PREFIX):
            k = k[k.index(const.V2_HEADER_PREFIX) + len(const.V2_HEADER_PREFIX):]
            v = util.decode_item(v)
            flag = 1
        elif k.startswith(const.OBS_META_HEADER_PREFIX):
            k = k[k.index(const.OBS_META_HEADER_PREFIX) + len(const.OBS_META_HEADER_PREFIX):]
            k = util.decode_item(k)
            v = util.decode_item(v)
            flag = 1
        elif k.startswith(const.OBS_HEADER_PREFIX):
            k = k[k.index(const.OBS_HEADER_PREFIX) + len(const.OBS_HEADER_PREFIX):]
            v = util.decode_item(v)
            flag = 1
        return flag, k, v

    def _rename_response_headers(self, headers):
        header = []
        for k, v in headers.items():
            flag = 0
            if k in const.ALLOWED_RESPONSE_HTTP_HEADER_METADATA_NAMES:
                flag = 1
            else:
                flag, k, v = self._rename_key(k, v)
            if flag:
                header.append((k, v))
        return header

    @staticmethod
    def _prepare_response_data(result, chuckSize):
        responseData = None
        while True:
            chunk = result.read(chuckSize)
            if not chunk:
                break
            responseData = chunk if responseData is None else responseData + chunk
        return responseData

    def _prepare_body(self, methodName, responseData, isJson, headers):
        body = None
        if methodName is not None:
            parseMethod = getattr(self.convertor, 'parse' + methodName[:1].upper() + methodName[1:])
            if parseMethod is not None:
                try:
                    if responseData:
                        responseData = responseData if const.IS_PYTHON2 else responseData.decode('UTF-8')
                        self.log_client.log(DEBUG, 'receive Msg:%s', responseData)
                        if not isJson:
                            search = self.pattern.search(responseData)
                            responseData = responseData if search is None else responseData.replace(search.group(),
                                                                                                    '')
                        body = parseMethod(responseData, headers)
                    else:
                        body = parseMethod(headers)
                except Exception as e:
                    self.log_client.log(ERROR, util.to_string(e))
                    self.log_client.log(ERROR, traceback.format_exc())
        return responseData, body

    @staticmethod
    def _prepare_request_id(requestId, headers):
        if requestId is None:
            requestId = headers.get('x-obs-request-id')
        if requestId is None:
            requestId = headers.get('x-amz-request-id')
        return requestId

    @staticmethod
    def _is_redirect_exception(status, headers):
        return 300 <= status < 400 and status != 304 and const.LOCATION_HEADER.lower() in headers

    def _parse_xml_internal(self, result, methodName=None, chuckSize=const.READ_ONCE_LENGTH, readable=False):
        status = util.to_int(result.status)
        reason = result.reason
        code = None
        message = None
        body = None
        requestId = None
        hostId = None
        resource = None
        headers = {}
        for k, v in result.getheaders():
            headers[k.lower()] = v
        responseData = self._prepare_response_data(result, chuckSize)

        header = self._rename_response_headers(headers)
        isJson = headers.get(const.CONTENT_TYPE_HEADER.lower(), 'xml') == const.MIME_TYPES.get('json')
        indicator = headers.get(self.ha.indicator_header())

        if status < 300:
            responseData, body = self._prepare_body(methodName, responseData, isJson, headers)
            requestId = self._prepare_request_id(None, headers)

        elif responseData:
            responseData = responseData if const.IS_PYTHON2 else responseData.decode('UTF-8')
            try:
                if isJson:
                    code, message, requestId = self.convertor.parseJsonErrorResult(responseData)
                else:
                    search = self.pattern.search(responseData)
                    responseData = responseData if search is None else responseData.replace(search.group(), '')
                    code, message, requestId, hostId, resource = self.convertor.parseErrorResult(responseData)
                body = responseData
            except Exception as ee:
                self.log_client.log(ERROR, util.to_string(ee))
                self.log_client.log(ERROR, traceback.format_exc())

        requestId = self._prepare_request_id(requestId, headers)

        self.log_client.log(DEBUG, 'http response result:status:%d,reason:%s,code:%s,message:%s,headers:%s',
                            status, reason, code, message, header)

        if status >= 300:
            self.log_client.log(ERROR, 'exceptional obs response:status:%d,reason:%s,code:%s,message:%s,requestId:%s',
                                status, reason, code, message, requestId)

        ret = GetResult(code=code, message=message, status=status, reason=reason, body=body,
                        requestId=requestId, hostId=hostId, resource=resource, header=header, indicator=indicator)

        if not readable:
            if self._is_redirect_exception(status, headers):
                location = headers.get(const.LOCATION_HEADER.lower())
                self.log_client.log(WARNING, 'http code is %d, need to redirect to %s', status, location)
                raise _RedirectException('http code is {0}, need to redirect to {1}'.format(status, location), location,
                                         ret)

            if status >= 500:
                raise _InternalException(ret)
        return ret


class _CreateSignedUrlResponse(BaseModel):
    allowedAttr = {'signedUrl': const.BASESTRING, 'actualSignedRequestHeaders': dict}


class _CreatePostSignatureResponse(BaseModel):
    allowedAttr = {'originPolicy': const.BASESTRING, 'policy': const.BASESTRING,
                   'credential': const.BASESTRING, 'date': const.BASESTRING, 'signature': const.BASESTRING,
                   'accessKeyId': const.BASESTRING}


class ObsClient(_BasicClient):

    def __init__(self, *args, **kwargs):
        super(ObsClient, self).__init__(*args, **kwargs)

    def _prepareParameterForSignedUrl(self, specialParam, expires, headers, queryParams):

        headers = {} if headers is None or not isinstance(headers, dict) else headers.copy()
        queryParams = {} if queryParams is None or not isinstance(queryParams, dict) else queryParams.copy()

        _headers = {}
        for k, v in headers.items():
            if k is not None and k != '':
                _headers[k] = v

        _queryParams = self._prepareParameterForSignedUrlQuery(queryParams, specialParam)

        expires = 300 if expires is None else util.to_int(expires)

        return _headers, _queryParams, expires, self.calling_format

    def _prepareParameterForSignedUrlQuery(self, queryParams, specialParam):
        _queryParams = {}
        for k, v in queryParams.items():
            if k is not None and k != '':
                _queryParams[k] = v

        if specialParam is not None:
            specialParam = 'storageClass' if self.signature.lower() == 'obs' and specialParam == 'storagePolicy' \
                else 'storagePolicy' if self.signature.lower() != 'obs' and specialParam == 'storageClass' \
                else specialParam
            _queryParams[specialParam] = None

        return _queryParams

    def createSignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None,
                        queryParams=None):
        delegate = self._createV4SignedUrl if self.signature.lower() == 'v4' else self._createV2SignedUrl
        return delegate(method, bucketName, objectKey, specialParam, expires, headers, queryParams)

    def createV2SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None,
                          queryParams=None):
        return self._createV2SignedUrl(method, bucketName, objectKey, specialParam, expires, headers, queryParams)

    def createV4SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None,
                          queryParams=None):
        return self._createV4SignedUrl(method, bucketName, objectKey, specialParam, expires, headers, queryParams)

    def _createV2SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None,
                           queryParams=None):

        headers, queryParams, expires, calling_format = self._prepareParameterForSignedUrl(specialParam, expires,
                                                                                           headers, queryParams)

        connect_server = self.server if self.is_cname else calling_format.get_server(self.server, bucketName)

        headers[const.HOST_HEADER] = '%s:%s' % (
            connect_server, self.port) if self.port != 443 and self.port != 80 else connect_server

        expires += util.to_int(time.time())

        securityProvider = self._get_token()
        if securityProvider.security_token is not None and self.ha.security_token_header() not in queryParams:
            queryParams[self.ha.security_token_header()] = securityProvider.security_token

        v2Auth = auth.Authentication(securityProvider.access_key_id, securityProvider.secret_access_key,
                                     self.path_style, self.ha, self.server, self.is_cname)

        signature = v2Auth.getSignature(method, bucketName, objectKey, queryParams,
                                        headers, util.to_string(expires))['Signature']

        queryParams['Expires'] = expires
        queryParams['AccessKeyId' if self.signature == 'obs' else 'AWSAccessKeyId'] = securityProvider.access_key_id
        queryParams['Signature'] = signature

        if self.is_cname:
            bucketName = None

        result = {'signedUrl': calling_format.get_full_url(self.is_secure, self.server,
                                                           self.port, bucketName, objectKey,
                                                           queryParams),
                  'actualSignedRequestHeaders': headers}

        return _CreateSignedUrlResponse(**result)

    def _createV4SignedUrl(self, method, bucketName=None, objectKey=None, specialParam=None, expires=300, headers=None,
                           queryParams=None):
        from datetime import datetime

        headers, queryParams, expires, calling_format = self._prepareParameterForSignedUrl(specialParam, expires,
                                                                                           headers, queryParams)

        if self.is_cname:
            connect_server = self.server
            bucketName = None
        else:
            connect_server = calling_format.get_server(self.server, bucketName)

        headers[const.HOST_HEADER] = '%s:%s' % (
            connect_server, self.port) if self.port != 443 and self.port != 80 else connect_server

        date = headers[const.DATE_HEADER] if const.DATE_HEADER in headers else headers.get(const.DATE_HEADER.lower())
        date = datetime.strptime(date, const.GMT_DATE_FORMAT) if date else datetime.utcnow()
        shortDate = date.strftime(const.SHORT_DATE_FORMAT)
        longDate = date.strftime(const.LONG_DATE_FORMAT)

        securityProvider = self._get_token()

        if securityProvider.security_token is not None and self.ha.security_token_header() not in queryParams:
            queryParams[self.ha.security_token_header()] = securityProvider.security_token

        v4Auth = auth.V4Authentication(securityProvider.access_key_id, securityProvider.secret_access_key, self.region,
                                       shortDate, longDate, self.path_style, self.ha)

        queryParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
        queryParams['X-Amz-Credential'] = v4Auth.getCredential()
        queryParams['X-Amz-Date'] = longDate
        queryParams['X-Amz-Expires'] = expires

        headMap = v4Auth.setMapKeyLower(headers)
        signedHeaders = v4Auth.getSignedHeaders(headMap)

        queryParams['X-Amz-SignedHeaders'] = signedHeaders

        signature = v4Auth.getSignature(method, bucketName, objectKey, queryParams,
                                        headMap, signedHeaders, 'UNSIGNED-PAYLOAD')['Signature']

        queryParams['X-Amz-Signature'] = signature

        if self.is_cname:
            bucketName = None

        result = {
            'signedUrl': calling_format.get_full_url(self.is_secure, self.server, self.port, bucketName, objectKey,
                                                     queryParams),
            'actualSignedRequestHeaders': headers
        }

        return _CreateSignedUrlResponse(**result)

    def createV4PostSignature(self, bucketName=None, objectKey=None, expires=300, formParams=None):
        return self._createPostSignature(bucketName, objectKey, expires, formParams, True)

    def createPostSignature(self, bucketName=None, objectKey=None, expires=300, formParams=None):
        return self._createPostSignature(bucketName, objectKey, expires, formParams, self.signature.lower() == 'v4')

    def _createPostSignature(self, bucketName=None, objectKey=None, expires=300, formParams=None, is_v4=False):
        from datetime import datetime, timedelta

        date = datetime.utcnow()
        shortDate = date.strftime(const.SHORT_DATE_FORMAT)
        longDate = date.strftime(const.LONG_DATE_FORMAT)
        securityProvider = self._get_token()

        expires = 300 if expires is None else util.to_int(expires)
        expires = date + timedelta(seconds=expires)

        expires = expires.strftime(const.EXPIRATION_DATE_FORMAT)

        formParams = self._parse_post_params(formParams, securityProvider, is_v4,
                                             bucketName, objectKey, longDate, shortDate)

        policy = ['{"expiration":"']
        policy.append(expires)
        policy.append('", "conditions":[')

        matchAnyBucket = True
        matchAnyKey = True

        conditionAllowKeys = ['acl', 'bucket', 'key', 'success_action_redirect', 'redirect', 'success_action_status']

        for key, value in formParams.items():
            if key:
                key = util.to_string(key).lower()

                if key == 'bucket':
                    matchAnyBucket = False
                elif key == 'key':
                    matchAnyKey = False

                if key not in const.ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES \
                        and not key.startswith(self.ha._get_header_prefix()) \
                        and not key.startswith(const.OBS_HEADER_PREFIX) and key not in conditionAllowKeys:
                    continue

                policy.append('{"')
                policy.append(key)
                policy.append('":"')
                policy.append(util.to_string(value))
                policy.append('"},')

        if matchAnyBucket:
            policy.append('["starts-with", "$bucket", ""],')

        if matchAnyKey:
            policy.append('["starts-with", "$key", ""],')

        policy.append(']}')

        originPolicy = ''.join(policy)

        policy = util.base64_encode(originPolicy)

        result = self._parse_post_signature_type(is_v4, securityProvider, originPolicy,
                                                 policy, formParams, shortDate, longDate)
        return _CreatePostSignatureResponse(**result)

    def _parse_post_params(self, formParams, securityProvider, is_v4, bucketName, objectKey, longDate, shortDate):
        formParams = {} if formParams is None or not isinstance(formParams,
                                                                dict) else formParams.copy()

        if securityProvider.security_token is not None and self.ha.security_token_header() not in formParams:
            formParams[
                self.ha.security_token_header()] = securityProvider.security_token

        if is_v4:
            formParams['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256'
            formParams['X-Amz-Date'] = longDate
            formParams['X-Amz-Credential'] = '%s/%s/%s/s3/aws4_request' % (
                securityProvider.access_key_id, shortDate, self.region)

        if bucketName:
            formParams['bucket'] = bucketName

        if objectKey:
            formParams['key'] = objectKey
        return formParams

    def _parse_post_signature_type(self, is_v4, securityProvider, originPolicy, policy, formParams,
                                   shortDate, longDate):
        if is_v4:
            v4Auth = auth.V4Authentication(securityProvider.access_key_id, securityProvider.secret_access_key,
                                           self.region, shortDate, longDate,
                                           self.path_style, self.ha)
            signingKey = v4Auth.getSigningKey_python2() if const.IS_PYTHON2 else v4Auth.getSigningKey_python3()
            signature = v4Auth.hmacSha256(signingKey, policy if const.IS_PYTHON2 else policy.encode('UTF-8'))
            result = {'originPolicy': originPolicy, 'policy': policy, 'algorithm': formParams['X-Amz-Algorithm'],
                      'credential': formParams['X-Amz-Credential'], 'date': formParams['X-Amz-Date'],
                      'signature': signature}
        else:
            v2Auth = auth.Authentication(securityProvider.access_key_id, securityProvider.secret_access_key,
                                         self.path_style, self.ha, self.server, self.is_cname)
            signature = v2Auth.hmacSha128(policy)
            result = {'originPolicy': originPolicy, 'policy': policy, 'signature': signature,
                      'accessKeyId': securityProvider.access_key_id}
        return result

    def bucketClient(self, bucketName):
        return BucketClient(self, bucketName)

    def _getApiVersion(self, bucketName=''):
        res = self._make_head_request(bucketName, pathArgs={'apiversion': None}, skipAuthentication=True)
        if res.status >= 500 or res.status == 404:
            return '', res
        if not hasattr(res, 'header'):
            return const.V2_SIGNATURE, res
        header = dict(res.header)
        if header.get('api', '0.0') >= '3.0' or header.get('x-obs-api', '0.0') >= '3.0':
            return const.OBS_SIGNATURE, res
        return const.V2_SIGNATURE, res

    @funcCache
    def listBuckets(self, isQueryLocation=True, extensionHeaders=None, bucketType=None):
        """
        Obtain a bucket list.
        :param isQueryLocation: Whether to query the bucket location.
        :param extensionHeaders: Other headers
        :param bucketType: Type of the buckets you want to list. The value can be OBJECT or POSIX, or be left blank.
               "OBJECT": To list common buckets.
               "POSIX": To list parallel file systems.
                If this parameter is left blank, both buckets and parallel file systems will be listed.
        :return: A bucket list
        """
        if self.is_cname:
            raise Exception('listBuckets is not allowed in custom domain mode')
        return self._make_get_request(methodName='listBuckets', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_list_buckets(isQueryLocation=isQueryLocation,
                                                                          bucketType=bucketType))

    @funcCache
    def createBucket(self, bucketName, header=None, location=None, extensionHeaders=None):
        if header is None:
            header = CreateBucketHeader()
        if self.is_cname:
            raise Exception('createBucket is not allowed in custom domain mode')
        res = self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                     **self.convertor.trans_create_bucket(header=header, location=location))
        try:
            if self.is_signature_negotiation and res.status == 400 and \
                    res.errorMessage == 'Unsupported Authorization Type' and \
                    self.thread_local.signature == const.OBS_SIGNATURE:
                self.thread_local.signature = const.V2_SIGNATURE
                res = self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                             **self.convertor.trans_create_bucket(header=header, location=location))
        finally:
            return res

    @funcCache
    def listObjects(self, bucketName, prefix=None, marker=None, max_keys=None, delimiter=None,
                    extensionHeaders=None, encoding_type=None):
        return self._make_get_request(bucketName, methodName='listObjects', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_list_objects(prefix=prefix, marker=marker,
                                                                          max_keys=max_keys, delimiter=delimiter,
                                                                          encoding_type=encoding_type))

    @funcCache
    def headBucket(self, bucketName, extensionHeaders=None):
        return self._make_head_request(bucketName, extensionHeaders=extensionHeaders)

    @funcCache
    def headObject(self, bucketName, objectKey, versionId=None, extensionHeaders=None):
        pathArgs = {}
        if versionId:
            pathArgs[const.VERSION_ID_PARAM] = util.to_string(versionId)
        return self._make_head_request(bucketName, objectKey, pathArgs=pathArgs, extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketMetadata(self, bucketName, origin=None, requestHeaders=None, extensionHeaders=None):
        return self._make_head_request(bucketName, methodName='getBucketMetadata', extensionHeaders=extensionHeaders,
                                       **self.convertor.trans_get_bucket_metadata(origin=origin,
                                                                                  requestHeaders=requestHeaders))

    @funcCache
    def getBucketLocation(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'location': None}, methodName='getBucketLocation',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucket(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketQuota(self, bucketName, quota, extensionHeaders=None):
        self._assert_not_null(quota, 'quota is empty')
        return self._make_put_request(bucketName, pathArgs={'quota': None}, entity=self.convertor.trans_quota(quota),
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketQuota(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'quota': None}, methodName='getBucketQuota',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketStorageInfo(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'storageinfo': None}, methodName='getBucketStorageInfo',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketAcl(self, bucketName, acl=None, aclControl=None, extensionHeaders=None):
        if acl is None:
            acl = ACL()
        if acl is not None and len(acl) > 0 and aclControl is not None:
            raise Exception('Both acl and aclControl are set')
        if not acl and not aclControl:
            raise Exception('Both acl and aclControl are not set')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_acl(acl=acl, aclControl=aclControl))

    @funcCache
    def getBucketAcl(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'acl': None}, methodName='getBucketAcl',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketPolicy(self, bucketName, policyJSON, extensionHeaders=None):
        self._assert_not_null(policyJSON, 'policyJSON is empty')
        return self._make_put_request(bucketName, pathArgs={'policy': None}, entity=policyJSON,
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketPolicy(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'policy': None}, methodName='getBucketPolicy',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucketPolicy(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'policy': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketVersioning(self, bucketName, status, extensionHeaders=None):
        self._assert_not_null(status, 'status is empty')
        return self._make_put_request(bucketName, pathArgs={'versioning': None},
                                      entity=self.convertor.trans_version_status(status),
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketVersioning(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'versioning': None}, methodName='getBucketVersioning',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def listVersions(self, bucketName, version=None, extensionHeaders=None):
        if version is None:
            version = Versions()
        return self._make_get_request(bucketName, methodName='listVersions', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_list_versions(version=version))

    @funcCache
    def listMultipartUploads(self, bucketName, multipart=None, extensionHeaders=None,
                             encoding_type=None):
        if multipart is None:
            multipart = ListMultipartUploadsRequest()
        return self._make_get_request(bucketName, methodName='listMultipartUploads', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_list_multipart_uploads(multipart=multipart,
                                                                                    encoding_type=encoding_type))

    @funcCache
    def deleteBucketLifecycle(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'lifecycle': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketLifecycle(self, bucketName, lifecycle, extensionHeaders=None):
        self._assert_not_null(lifecycle, 'lifecycle is empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_lifecycle(lifecycle=lifecycle))

    @funcCache
    def getBucketLifecycle(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'lifecycle': None}, methodName='getBucketLifecycle',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucketWebsite(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'website': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketWebsite(self, bucketName, website, extensionHeaders=None):
        self._assert_not_null(website, 'website is empty')
        return self._make_put_request(bucketName, pathArgs={'website': None},
                                      entity=self.convertor.trans_website(website), extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketWebsite(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'website': None}, methodName='getBucketWebsite',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketLogging(self, bucketName, logstatus=None, extensionHeaders=None):
        if logstatus is None:
            logstatus = Logging()
        return self._make_put_request(bucketName, pathArgs={'logging': None},
                                      entity=self.convertor.trans_logging(logstatus), extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketLogging(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'logging': None}, methodName='getBucketLogging',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketTagging(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'tagging': None}, methodName='getBucketTagging',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketTagging(self, bucketName, tagInfo, extensionHeaders=None):
        self._assert_not_null(tagInfo, 'tagInfo is empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_tagging(tagInfo=tagInfo))

    @funcCache
    def deleteBucketTagging(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'tagging': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketCors(self, bucketName, corsRuleList, extensionHeaders=None):
        self._assert_not_null(corsRuleList, 'corsRuleList is empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_cors(corsRuleList=corsRuleList))

    @funcCache
    def deleteBucketCors(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'cors': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketCors(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'cors': None}, methodName='getBucketCors',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def optionsBucket(self, bucketName, option, extensionHeaders=None):
        return self.optionsObject(bucketName, None, option=option, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketNotification(self, bucketName, notification=None, extensionHeaders=None):
        if notification is None:
            notification = Notification()
        if notification is None:
            notification = Notification()
        return self._make_put_request(bucketName, pathArgs={'notification': None},
                                      entity=self.convertor.trans_notification(notification),
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketNotification(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'notification': None}, methodName='getBucketNotification',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def optionsObject(self, bucketName, objectKey, option, extensionHeaders=None):
        headers = {}
        if option is not None:
            if option.get('origin') is not None:
                headers[const.ORIGIN_HEADER] = util.to_string(option['origin'])
            if option.get('accessControlRequestMethods') is not None:
                headers[const.ACCESS_CONTROL_REQUEST_METHOD_HEADER] = option['accessControlRequestMethods']
            if option.get('accessControlRequestHeaders') is not None:
                headers[const.ACCESS_CONTROL_REQUEST_HEADERS_HEADER] = option['accessControlRequestHeaders']
        return self._make_options_request(bucketName, objectKey, headers=headers, methodName='optionsBucket',
                                          extensionHeaders=extensionHeaders)

    @funcCache
    def getObjectMetadata(self, bucketName, objectKey, versionId=None, sseHeader=None, origin=None, requestHeaders=None,
                          extensionHeaders=None):
        pathArgs = {}
        if versionId:
            pathArgs[const.VERSION_ID_PARAM] = util.to_string(versionId)
        headers = {}
        if origin:
            headers[const.ORIGIN_HEADER] = util.to_string(origin)
        _requestHeaders = requestHeaders[0] if isinstance(requestHeaders, list) and len(
            requestHeaders) == 1 else requestHeaders
        if _requestHeaders:
            headers[const.ACCESS_CONTROL_REQUEST_HEADERS_HEADER] = util.to_string(_requestHeaders)
        return self._make_head_request(bucketName, objectKey, pathArgs=pathArgs,
                                       headers=self.convertor._set_sse_header(sseHeader, headers=headers,
                                                                              onlySseCHeader=True),
                                       methodName='getObjectMetadata', extensionHeaders=extensionHeaders)

    @funcCache
    def setObjectMetadata(self, bucketName, objectKey, metadata=None, headers=None, versionId=None,
                          extensionHeaders=None):
        if headers is None:
            headers = SetObjectMetadataHeader()

        return self._make_put_request(bucketName, objectKey, methodName='setObjectMetadata',
                                      extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_object_metadata(metadata=metadata, headers=headers,
                                                                                 versionId=versionId))

    @funcCache
    def getObject(self, bucketName, objectKey, downloadPath=None, getObjectRequest=None,
                  headers=None, loadStreamInMemory=False, progressCallback=None, extensionHeaders=None, notifier=None):
        if getObjectRequest is None:
            getObjectRequest = GetObjectRequest()
        if headers is None:
            headers = GetObjectHeader()
        _parse_content = self._parse_content
        CHUNK_SIZE = self.chunk_size
        readable = False if progressCallback is None else True

        def parseMethod(conn):
            result = conn.getresponse()
            return _parse_content(objectKey, conn, result, download_start=headers.range, downloadPath=downloadPath,
                                  chuckSize=CHUNK_SIZE, loadStreamInMemory=loadStreamInMemory, notifier=notifier,
                                  progressCallback=progressCallback)

        return self._make_get_request(bucketName, objectKey, parseMethod=parseMethod, readable=readable,
                                      extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_get_object(getObjectRequest=getObjectRequest,
                                                                        headers=headers))

    @staticmethod
    def _prepare_append_object_input(objectKey, headers, content):
        objectKey = util.safe_encode(objectKey)
        if objectKey is None:
            objectKey = ''

        if headers is None:
            headers = AppendObjectHeader()

        if content is None:
            content = AppendObjectContent()

        if headers.get('contentType') is None:
            headers['contentType'] = const.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:].lower())

        return objectKey, headers, content

    def _prepare_file_notifier_and_entity(self, offset, file_size, headers, progressCallback, file_path, readable):
        if offset is not None and 0 < offset < file_size:
            headers['contentLength'] = headers['contentLength'] if 0 < headers['contentLength'] <= (
                    file_size - offset) else file_size - offset
            totalCount = headers['contentLength']
            if totalCount > 0 and progressCallback is not None:
                readable = True
                notifier = progress.ProgressNotifier(progressCallback, totalCount)
            else:
                notifier = progress.NONE_NOTIFIER
            readable_object = self.gen_readable_object_from_file(file_path)
            readable_object.seek(offset)
            entity = util.get_entity_for_send_with_total_count(readable_object, totalCount, self.chunk_size, notifier)
        else:
            totalCount = headers['contentLength']
            if totalCount > 0 and progressCallback is not None:
                readable = True
                notifier = progress.ProgressNotifier(progressCallback, totalCount)
            else:
                notifier = progress.NONE_NOTIFIER
            readable_object = self.gen_readable_object_from_file(file_path)
            entity = util.get_entity_for_send_with_total_count(readable_object, totalCount, self.chunk_size, notifier)

        return headers, readable, notifier, entity

    def _prepare_content_notifier_and_entity(self, entity, headers, progressCallback, autoClose, readable, chunkedMode,
                                             notifier):
        if entity is None:
            entity = ''
        elif hasattr(entity, 'read') and callable(entity.read):
            readable = True
            if headers.get('contentLength') is None:
                chunkedMode = True
                notifier = progress.ProgressNotifier(progressCallback,
                                                     -1) if progressCallback is not None else progress.NONE_NOTIFIER
                entity = util.get_readable_entity(entity, self.chunk_size, notifier, autoClose)
            else:
                totalCount = util.to_long(headers.get('contentLength'))
                notifier = progress.ProgressNotifier(progressCallback,
                                                     totalCount) if totalCount > 0 and progressCallback is not None \
                    else progress.NONE_NOTIFIER
                entity = util.get_entity_for_send_with_total_count(entity, totalCount, self.chunk_size, notifier,
                                                                   autoClose)

        return entity, readable, chunkedMode, notifier

    @funcCache
    def appendObject(self, bucketName, objectKey, content=None, metadata=None, headers=None, progressCallback=None,
                     autoClose=True, extensionHeaders=None):
        objectKey, headers, content = self._prepare_append_object_input(objectKey, headers, content)

        chunkedMode = False
        readable = False
        notifier = None
        if content.get('isFile'):
            file_path = self.check_file_path(content.get('content'))

            if headers.get('contentType') is None:
                headers['contentType'] = const.MIME_TYPES.get(file_path[file_path.rfind('.') + 1:].lower())

            file_size = util.to_long(os.path.getsize(file_path))
            headers['contentLength'] = util.to_long(headers.get('contentLength'))
            headers['contentLength'] = headers['contentLength'] if headers.get('contentLength') is not None and headers[
                'contentLength'] <= file_size else file_size
            offset = util.to_long(content.get('offset'))
            headers, readable, notifier, entity = self._prepare_file_notifier_and_entity(offset, file_size, headers,
                                                                                         progressCallback, file_path,
                                                                                         readable)
            headers = self.convertor.trans_put_object(metadata=metadata, headers=headers)
            self.log_client.log(DEBUG, 'send Path:%s' % file_path)
        else:
            entity = content.get('content')
            entity, readable, chunkedMode, notifier = self._prepare_content_notifier_and_entity(entity, headers,
                                                                                                progressCallback,
                                                                                                autoClose, readable,
                                                                                                chunkedMode, notifier)

            headers = self.convertor.trans_put_object(metadata=metadata, headers=headers)

        try:
            if notifier is not None:
                notifier.start()
            ret = self._make_post_request(bucketName, objectKey, pathArgs={'append': None, 'position': util.to_string(
                content['position']) if content.get('position') is not None else 0},
                                          headers=headers, entity=entity, chunkedMode=chunkedMode,
                                          methodName='appendObject', readable=readable,
                                          extensionHeaders=extensionHeaders)
        finally:
            if notifier is not None:
                notifier.end()
        self._generate_object_url(ret, bucketName, objectKey)
        return ret

    @funcCache
    def putContent(self, bucketName, objectKey, content=None, metadata=None, headers=None, progressCallback=None,
                   autoClose=True, extensionHeaders=None):
        objectKey = util.safe_encode(objectKey)
        if objectKey is None:
            objectKey = ''
        if headers is None:
            headers = PutObjectHeader()
        if headers.get('contentType') is None:
            headers['contentType'] = const.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:].lower())
        _headers = self.convertor.trans_put_object(metadata=metadata, headers=headers)

        readable = False
        chunkedMode = False
        notifier = None

        try:
            entity = content
            if entity is None:
                entity = ''
            elif hasattr(entity, 'read') and callable(entity.read):
                readable = True
                if headers.get('contentLength') is None:
                    chunkedMode = True
                    notifier = progress.ProgressNotifier(progressCallback,
                                                         -1) if progressCallback is not None else progress.NONE_NOTIFIER
                    entity = util.get_readable_entity(entity, self.chunk_size, notifier, autoClose)
                else:
                    totalCount = util.to_long(headers.get('contentLength'))
                    notifier = progress.ProgressNotifier(progressCallback,
                                                         totalCount) if totalCount > 0 and progressCallback \
                                                                        is not None else progress.NONE_NOTIFIER
                    entity = util.get_entity_for_send_with_total_count(entity, totalCount, self.chunk_size, notifier,
                                                                       autoClose)

                notifier.start()
            ret = self._make_put_request(bucketName, objectKey, headers=_headers, entity=entity,
                                         chunkedMode=chunkedMode, methodName='putContent', readable=readable,
                                         extensionHeaders=extensionHeaders)
        finally:
            if notifier is not None:
                notifier.end()
        self._generate_object_url(ret, bucketName, objectKey)
        return ret

    def putObject(self, bucketName, objectKey, content, metadata=None, headers=None, progressCallback=None,
                  autoClose=True, extensionHeaders=None):
        return self.putContent(bucketName, objectKey, content, metadata, headers, progressCallback, autoClose,
                               extensionHeaders=extensionHeaders)

    @funcCache
    def putFile(self, bucketName, objectKey, file_path, metadata=None, headers=None, progressCallback=None,
                extensionHeaders=None):
        file_path = self.check_file_path(file_path)
        _flag = os.path.isdir(file_path)

        if headers is None:
            headers = PutObjectHeader()
        if metadata is None:
            metadata = dict()

        if _flag:
            headers['contentLength'] = None
            headers['md5'] = None
            headers['contentType'] = None

            results = []
            for f in os.listdir(file_path):
                f = util.safe_encode(f)
                __file_path = os.path.join(file_path, f)
                if not objectKey:
                    key = util.safe_trans_to_gb2312('{0}/'.format(os.path.split(file_path)[1]) + f)
                else:
                    key = '{0}/'.format(objectKey) + util.safe_trans_to_gb2312(f)
                result = self.putFile(bucketName, key, __file_path, metadata, headers,
                                      extensionHeaders=extensionHeaders)
                results.append((key, result))
            return results

        if not objectKey:
            objectKey = os.path.split(file_path)[1]

        size = util.to_long(os.path.getsize(file_path))

        headers = self._putFileHandleHeader(headers, size, objectKey, file_path)

        readable_object = self.gen_readable_object_from_file(file_path)
        metadata = self.add_metadata_from_content(metadata, headers, readable_object)
        _headers = self.convertor.trans_put_object(metadata=metadata, headers=headers)
        if const.CONTENT_LENGTH_HEADER not in _headers:
            _headers[const.CONTENT_LENGTH_HEADER] = util.to_string(size)
        self.log_client.log(DEBUG, 'send Path:%s' % file_path)

        totalCount = util.to_long(headers['contentLength']) if headers.get('contentLength') is not None \
            else os.path.getsize(file_path)
        if totalCount > 0 and progressCallback is not None:
            notifier = progress.ProgressNotifier(progressCallback, totalCount)
            readable = True
        else:
            notifier = progress.NONE_NOTIFIER
            readable = False

        entity = util.get_entity_for_send_with_total_count(readable_object, totalCount, self.chunk_size, notifier)
        try:
            notifier.start()
            ret = self._make_put_request(bucketName, objectKey, headers=_headers, entity=entity,
                                         methodName='putContent', readable=readable, extensionHeaders=extensionHeaders)
        finally:
            notifier.end()
        self._generate_object_url(ret, bucketName, objectKey)
        return ret

    @staticmethod
    def add_metadata_from_content(metadata, headers, content):
        return metadata

    def gen_readable_object_from_file(self, file_path):
        return open(file_path, "rb")

    @staticmethod
    def _putFileHandleHeader(headers, size, objectKey, file_path):
        headers['contentLength'] = util.to_long(headers.get('contentLength'))
        if headers.get('contentLength') is not None:
            headers['contentLength'] = size if headers['contentLength'] > size else headers['contentLength']

        if headers.get('contentType') is None:
            headers['contentType'] = const.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:].lower())

        if headers.get('contentType') is None:
            headers['contentType'] = const.MIME_TYPES.get(file_path[file_path.rfind('.') + 1:].lower())
        return headers

    @staticmethod
    def _get_offset(offset, file_size):
        offset = offset if offset is not None and 0 <= offset < file_size else 0
        return offset

    @staticmethod
    def _get_part_size(partSize, file_size, offset):
        partSize = partSize if partSize is not None and 0 < partSize <= (file_size - offset) else file_size - offset
        return partSize

    def _prepare_headers(self, md5, isAttachMd5, file_path, partSize, offset, sseHeader, headers):
        if md5:
            headers[const.CONTENT_MD5_HEADER] = md5
        elif isAttachMd5:
            headers[const.CONTENT_MD5_HEADER] = util.base64_encode(
                util.md5_file_encode_by_size_offset(file_path, partSize, offset, self.chunk_size))

        if sseHeader is not None:
            self.convertor._set_sse_header(sseHeader, headers, True)

        return headers

    @staticmethod
    def _prepare_upload_part_notifier(partSize, progressCallback, readable):
        if partSize > 0 and progressCallback is not None:
            readable = True
            notifier = progress.ProgressNotifier(progressCallback, partSize)
        else:
            notifier = progress.NONE_NOTIFIER

        return readable, notifier

    def _get_headers(self, md5, sseHeader, headers):
        if md5:
            headers[const.CONTENT_MD5_HEADER] = md5
        if sseHeader is not None:
            self.convertor._set_sse_header(sseHeader, headers, True)

        return headers

    @staticmethod
    def _get_notifier_without_size(progressCallback):
        return progress.ProgressNotifier(progressCallback,
                                         -1) if progressCallback is not None else progress.NONE_NOTIFIER

    @staticmethod
    def _get_notifier_with_size(progressCallback, totalCount):
        return progress.ProgressNotifier(progressCallback,
                                         totalCount) if totalCount > 0 and progressCallback is not None \
            else progress.NONE_NOTIFIER

    def _check_file_part_info(self, file_path, offset, partSize):
        file_part_info = dict()
        file_part_info["file_path"] = self.check_file_path(file_path)
        file_size = util.to_long(os.path.getsize(file_path))
        offset = util.to_long(offset)
        file_part_info["offset"] = self._get_offset(offset, file_size)
        partSize = util.to_long(partSize)
        file_part_info["partSize"] = self._get_part_size(partSize, file_size, offset)
        return file_part_info

    @funcCache
    def uploadPart(self, bucketName, objectKey, partNumber, uploadId, object=None, isFile=False, partSize=None,
                   offset=0, sseHeader=None, isAttachMd5=False, md5=None, content=None, progressCallback=None,
                   autoClose=True, extensionHeaders=None):
        self._assert_not_null(partNumber, 'partNumber is empty')
        self._assert_not_null(uploadId, 'uploadId is empty')

        chunkedMode = False
        readable = False

        if content is None:
            content = object

        notifier = None
        if isFile:
            checked_file_part_info = self._check_file_part_info(content, offset, partSize)

            headers = {const.CONTENT_LENGTH_HEADER: util.to_string(checked_file_part_info["partSize"])}
            headers = self._prepare_headers(md5, isAttachMd5, checked_file_part_info["file_path"],
                                            checked_file_part_info["partSize"], checked_file_part_info["offset"],
                                            sseHeader, headers)

            readable, notifier = self._prepare_upload_part_notifier(checked_file_part_info["partSize"],
                                                                    progressCallback, readable)
            readable_object = open(checked_file_part_info["file_path"], "rb")
            readable_object.seek(checked_file_part_info["offset"])
            entity = util.get_entity_for_send_with_total_count(readable_object, checked_file_part_info["partSize"],
                                                               self.chunk_size, notifier)
        else:
            headers = {}
            if content is not None and hasattr(content, 'read') and callable(content.read):
                readable = True
                headers = self._get_headers(md5, sseHeader, headers)

                if partSize is None:
                    self.log_client.log(DEBUG, 'missing partSize when uploading a readable stream')
                    chunkedMode = True
                    notifier = self._get_notifier_without_size(progressCallback)
                    entity = util.get_readable_entity(content, self.chunk_size, notifier, autoClose)
                else:
                    headers[const.CONTENT_LENGTH_HEADER] = util.to_string(partSize)
                    totalCount = util.to_long(partSize)
                    notifier = self._get_notifier_with_size(progressCallback, totalCount)
                    entity = util.get_entity_for_send_with_total_count(content, totalCount, self.chunk_size, notifier,
                                                                       autoClose)
            else:
                entity = content
                if entity is None:
                    entity = ''
                headers = self._get_headers(md5, sseHeader, headers)

        try:
            if notifier is not None:
                notifier.start()
            ret = self._make_put_request(bucketName, objectKey,
                                         pathArgs={'partNumber': partNumber, 'uploadId': uploadId},
                                         headers=headers, entity=entity, chunkedMode=chunkedMode,
                                         methodName='uploadPart', readable=readable, extensionHeaders=extensionHeaders)
        finally:
            if notifier is not None:
                notifier.end()
        return ret

    @staticmethod
    def check_file_path(file_path):
        file_path = util.safe_encode(file_path)
        if not os.path.exists(file_path):
            file_path = util.safe_trans_to_gb2312(file_path)
            if not os.path.exists(file_path):
                raise Exception('file [%s] does not exist' % file_path)
        return file_path

    @funcCache
    def _uploadPartWithNotifier(self, bucketName, objectKey, partNumber, uploadId, content=None, isFile=False,
                                partSize=None, offset=0, sseHeader=None, isAttachMd5=False, md5=None, notifier=None,
                                extensionHeaders=None, headers=None):
        self._assert_not_null(partNumber, 'partNumber is empty')
        self._assert_not_null(uploadId, 'uploadId is empty')

        chunkedMode = False
        readable = False
        if headers is None:
            headers = dict()
        if isFile:
            checked_file_part_info = self._check_file_part_info(content, offset, partSize)

            headers[const.CONTENT_LENGTH_HEADER] = util.to_string(checked_file_part_info["partSize"])
            headers = self._prepare_headers(md5, isAttachMd5, checked_file_part_info["file_path"],
                                            checked_file_part_info["partSize"], checked_file_part_info["offset"],
                                            sseHeader, headers)

            if notifier is not None and not isinstance(notifier, progress.NoneNotifier):
                readable = True
            readable_object = open(checked_file_part_info["file_path"], "rb")
            readable_object.seek(checked_file_part_info["offset"])
            entity = util.get_entity_for_send_with_total_count(readable_object, partSize, self.chunk_size, notifier)
        else:
            if content is not None and hasattr(content, 'read') and callable(content.read):
                readable = True
                headers = self._get_headers(md5, sseHeader, headers)

                if partSize is None:
                    chunkedMode = True
                    entity = util.get_readable_entity(content, self.chunk_size, notifier)
                else:
                    headers[const.CONTENT_LENGTH_HEADER] = util.to_string(partSize)
                    entity = util.get_entity_for_send_with_total_count(content, util.to_long(partSize), self.chunk_size,
                                                                       notifier)
            else:
                entity = content
                if entity is None:
                    entity = ''
                headers = self._get_headers(md5, sseHeader, headers)

        ret = self._make_put_request(bucketName, objectKey, pathArgs={'partNumber': partNumber, 'uploadId': uploadId},
                                     headers=headers, entity=entity, chunkedMode=chunkedMode, methodName='uploadPart',
                                     readable=readable, extensionHeaders=extensionHeaders)
        return ret

    @funcCache
    def copyObject(self, sourceBucketName, sourceObjectKey, destBucketName, destObjectKey, metadata=None, headers=None,
                   versionId=None, extensionHeaders=None):
        self._assert_not_null(sourceBucketName, 'sourceBucketName is empty')
        sourceObjectKey = util.safe_encode(sourceObjectKey)
        if sourceObjectKey is None:
            sourceObjectKey = ''
        destObjectKey = util.safe_encode(destObjectKey)
        if destObjectKey is None:
            destObjectKey = ''

        if headers is None:
            headers = CopyObjectHeader()

        return self._make_put_request(destBucketName, destObjectKey,
                                      methodName='copyObject', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_copy_object(metadata=metadata, headers=headers,
                                                                         versionId=versionId,
                                                                         sourceBucketName=sourceBucketName,
                                                                         sourceObjectKey=sourceObjectKey))

    @funcCache
    def setObjectAcl(self, bucketName, objectKey, acl=None, versionId=None, aclControl=None, extensionHeaders=None):
        if acl is None:
            acl = ACL()
        if acl is not None and len(acl) > 0 and aclControl is not None:
            raise Exception('Both acl and aclControl are set')
        if not acl and not aclControl:
            raise Exception('Both acl and aclControl are not set')
        return self._make_put_request(bucketName, objectKey, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_object_acl(acl=acl, versionId=versionId,
                                                                            aclControl=aclControl))

    @funcCache
    def getObjectAcl(self, bucketName, objectKey, versionId=None, extensionHeaders=None):
        pathArgs = {'acl': None}
        if versionId:
            pathArgs[const.VERSION_ID_PARAM] = util.to_string(versionId)

        return self._make_get_request(bucketName, objectKey, pathArgs=pathArgs, methodName='getObjectAcl',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteObject(self, bucketName, objectKey, versionId=None, extensionHeaders=None):
        path_args = {}
        if versionId:
            path_args[const.VERSION_ID_PARAM] = util.to_string(versionId)
        return self._make_delete_request(bucketName, objectKey, pathArgs=path_args, methodName='deleteObject',
                                         extensionHeaders=extensionHeaders)

    @funcCache
    def deleteObjects(self, bucketName, deleteObjectsRequest, extensionHeaders=None):
        self._assert_not_null(deleteObjectsRequest, 'deleteObjectsRequest is empty')
        return self._make_post_request(bucketName, methodName='deleteObjects', extensionHeaders=extensionHeaders,
                                       **self.convertor.trans_delete_objects(deleteObjectsRequest=deleteObjectsRequest))

    @funcCache
    def restoreObject(self, bucketName, objectKey, days, tier=None, versionId=None, extensionHeaders=None):
        self._assert_not_null(days, 'days is empty')
        return self._make_post_request(bucketName, objectKey, extensionHeaders=extensionHeaders,
                                       **self.convertor.trans_restore_object(days=days, tier=tier, versionId=versionId))

    @funcCache
    def initiateMultipartUpload(self, bucketName, objectKey, acl=None, storageClass=None,
                                metadata=None, websiteRedirectLocation=None, contentType=None, sseHeader=None,
                                expires=None, extensionGrants=None, extensionHeaders=None, encoding_type=None):
        objectKey = util.safe_encode(objectKey)
        if objectKey is None:
            objectKey = ''

        if contentType is None:
            contentType = const.MIME_TYPES.get(objectKey[objectKey.rfind('.') + 1:].lower())

        return self._make_post_request(bucketName, objectKey, methodName='initiateMultipartUpload',
                                       extensionHeaders=extensionHeaders,
                                       **self.convertor.
                                       trans_initiate_multipart_upload(acl=acl,
                                                                       storageClass=storageClass,
                                                                       metadata=metadata,
                                                                       websiteRedirectLocation=websiteRedirectLocation,
                                                                       contentType=contentType,
                                                                       sseHeader=sseHeader,
                                                                       expires=expires,
                                                                       extensionGrants=extensionGrants,
                                                                       encoding_type=encoding_type)
                                       )

    @funcCache
    def copyPart(self, bucketName, objectKey, partNumber, uploadId, copySource, copySourceRange=None,
                 destSseHeader=None, sourceSseHeader=None, extensionHeaders=None):
        self._assert_not_null(partNumber, 'partNumber is empty')
        self._assert_not_null(uploadId, 'uploadId is empty')
        self._assert_not_null(copySource, 'copySource is empty')

        return self._make_put_request(bucketName, objectKey, methodName='copyPart', extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_copy_part(partNumber=partNumber, uploadId=uploadId,
                                                                       copySource=copySource,
                                                                       copySourceRange=copySourceRange,
                                                                       destSseHeader=destSseHeader,
                                                                       sourceSseHeader=sourceSseHeader))

    @funcCache
    def completeMultipartUpload(self, bucketName, objectKey, uploadId, completeMultipartUploadRequest,
                                extensionHeaders=None, encoding_type=None):
        self._assert_not_null(uploadId, 'uploadId is empty')
        self._assert_not_null(completeMultipartUploadRequest, 'completeMultipartUploadRequest is empty')
        pathArgs = {'uploadId': uploadId}
        if encoding_type is not None:
            pathArgs["encoding-type"] = encoding_type
        ret = self._make_post_request(bucketName, objectKey,
                                      pathArgs=pathArgs,
                                      entity=self.convertor.trans_complete_multipart_upload_request(
                                          completeMultipartUploadRequest), methodName='completeMultipartUpload',
                                      extensionHeaders=extensionHeaders)
        self._generate_object_url(ret, bucketName, objectKey)
        return ret

    @funcCache
    def abortMultipartUpload(self, bucketName, objectKey, uploadId, extensionHeaders=None):
        self._assert_not_null(uploadId, 'uploadId is empty')
        return self._make_delete_request(bucketName, objectKey, pathArgs={'uploadId': uploadId},
                                         extensionHeaders=extensionHeaders)

    @funcCache
    def listParts(self, bucketName, objectKey, uploadId, maxParts=None, partNumberMarker=None, extensionHeaders=None,
                  encoding_type=None):
        self._assert_not_null(uploadId, 'uploadId is empty')
        pathArgs = {'uploadId': uploadId}
        if maxParts is not None:
            pathArgs['max-parts'] = maxParts
        if partNumberMarker is not None:
            pathArgs['part-number-marker'] = partNumberMarker
        if encoding_type is not None:
            pathArgs['encoding-type'] = encoding_type
        return self._make_get_request(bucketName, objectKey, pathArgs=pathArgs, methodName='listParts',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketStoragePolicy(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, methodName='getBucketStoragePolicy',
                                      extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_get_bucket_storage_policy())

    @funcCache
    def setBucketStoragePolicy(self, bucketName, storageClass, extensionHeaders=None):
        self._assert_not_null(storageClass, 'storageClass is empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_storage_policy(storageClass=storageClass))

    @funcCache
    def setBucketEncryption(self, bucketName, encryption, key=None, extensionHeaders=None):
        self._assert_not_null(encryption, 'encryption is empty')
        return self._make_put_request(bucketName, pathArgs={'encryption': None},
                                      entity=self.convertor.trans_encryption(encryption=encryption, key=key),
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketEncryption(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, methodName='getBucketEncryption', pathArgs={'encryption': None},
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucketEncryption(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'encryption': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketReplication(self, bucketName, replication, extensionHeaders=None):
        self._assert_not_null(replication, 'replication is empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_replication(replication=replication))

    @funcCache
    def getBucketReplication(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'replication': None}, methodName='getBucketReplication',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucketReplication(self, bucketName, extensionHeaders=None):
        return self._make_delete_request(bucketName, pathArgs={'replication': None}, extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketRequestPayment(self, bucketName, payer, extensionHeaders=None):
        self._assert_not_null(payer, 'payer is empty')
        return self._make_put_request(bucketName, pathArgs={'requestPayment': None},
                                      entity=self.convertor.trans_bucket_request_payment(payer=payer),
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketRequestPayment(self, bucketName, extensionHeaders=None):
        return self._make_get_request(bucketName, pathArgs={'requestPayment': None},
                                      methodName='getBucketRequestPayment', extensionHeaders=extensionHeaders)

    # begin virtual bucket related
    # begin virtual bucket related
    # begin virtual bucket related

    @funcCache
    def listAvailableZoneInfo(self, regionId, token, extensionHeaders=None):
        self._assert_not_null(regionId, 'regionId should not be empty')
        self._assert_not_null(token, 'token should not be empty')

        pathArgs = {'regionId': regionId}
        header = {
            const.X_AUTH_TOKEN_HEADER: token,
            const.CONTENT_TYPE_HEADER: const.MIME_TYPES.get('json')
        }

        return self._make_get_request(
            objectKey='v1/services/clusters',
            pathArgs=pathArgs,
            headers=header,
            methodName=self.json_response_method_name,
            extensionHeaders=extensionHeaders
        )

    @funcCache
    def createBucketAlias(self, bucketName, aliasInfo=None, extensionHeaders=None):
        if aliasInfo is None:
            raise Exception('aliasInfo is None')
        self._assert_not_null(aliasInfo.get('bucket1'), 'bucket1 should not be empty')
        self._assert_not_null(aliasInfo.get('bucket2'), 'bucket2 should not be empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_alias(aliasInfo=aliasInfo))

    @funcCache
    def bindBucketAlias(self, bucketName, aliasInfo=None, extensionHeaders=None):
        if aliasInfo is None:
            raise Exception('aliasInfo is None')
        self._assert_not_null(aliasInfo.get('alias'), 'bucket alias should not be empty')
        return self._make_put_request(bucketName, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_bind_bucket_alias(aliasInfo=aliasInfo))

    @funcCache
    def deleteBucketAlias(self, bucketAlias, extensionHeaders=None):
        self._assert_not_null(bucketAlias, 'bucket alias should not be empty')
        pathArgs = {const.OBSBUCKETALIAS_PARAM: None}
        return self._make_delete_request(bucketName=bucketAlias, pathArgs=pathArgs, extensionHeaders=extensionHeaders)

    @funcCache
    def unbindBucketAlias(self, bucketName, extensionHeaders=None):
        pathArgs = {const.OBSALIAS_PARAM: None}
        return self._make_delete_request(bucketName, pathArgs=pathArgs, extensionHeaders=extensionHeaders)

    @funcCache
    def getBucketAlias(self, bucketName, extensionHeaders=None):
        pathArgs = {const.OBSALIAS_PARAM: None}
        return self._make_get_request(bucketName, pathArgs=pathArgs, methodName='getBucketAlias',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def listBucketAlias(self, extensionHeaders=None):
        pathArgs = {const.OBSBUCKETALIAS_PARAM: None}
        return self._make_get_request(pathArgs=pathArgs, methodName='ListBucketAlias',
                                      extensionHeaders=extensionHeaders)

    @funcCache
    def createVirtualBucket(self, regionId, token, bucketName1, bucketName2, bucketAlias, agencyName, header=None):
        # step 1: 列举指定region下的集群信息
        azResp = self.listAvailableZoneInfo(regionId, token)
        if azResp.status != 200:
            raise Exception('list AZ infos failed, resp: %s' % azResp)

        firstAZCgId, secondAZCgId = self._get_cluster_group_id(azResp)

        # step 2: 指定集群id创桶
        self._create_bucket_with_cluster_id(firstAZCgId, secondAZCgId, bucketName1, bucketName2, bucketAlias, header)

        # step 3: 创建一次别名
        aliasInfo = BucketAliasModel()
        aliasInfo.bucket1 = bucketName1
        aliasInfo.bucket2 = bucketName2
        cbaResp = self.createBucketAlias(bucketAlias, aliasInfo)
        if cbaResp.status != 200:
            self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED, bucketName1, bucketName2, bucketAlias)
            raise Exception('create bucket alias failed, resp: %s' % cbaResp)

        # step 4: 绑定两次别名，为两个真实桶分别绑定
        aliasInfo.alias = bucketAlias
        bindResp = self.bindBucketAlias(bucketName1, aliasInfo)
        if bindResp.status != 200:
            self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEALIAS_STAGED, bucketName1, bucketName2, bucketAlias)
            raise Exception('binding bucket alias failed, resp: %s' % bindResp)

        bindResp = self.bindBucketAlias(bucketName2, aliasInfo)
        if bindResp.status != 200:
            self._clear_virtual_bucket(const.VIRTUAL_BUCKET_BINDALIAS_STAGED, bucketName1, bucketName2, bucketAlias)
            raise Exception('binding bucket alias failed, resp: %s' % bindResp)

        # step 5: 双向配置复制关系，并开启历史对象复制
        replicationResp = self._set_virtual_replication(agencyName, bucketName1, bucketName2)
        if replicationResp.status != 200:
            self._clear_virtual_bucket(const.VIRTUAL_BUCKET_BINDALIAS_STAGED, bucketName1, bucketName2, bucketAlias)
            raise Exception('set replication failed, resp: %s' % replicationResp)

        replicationResp = self._set_virtual_replication(agencyName, bucketName2, bucketName1)
        if replicationResp.status != 200:
            self._clear_virtual_bucket(const.VIRTUAL_BUCKET_BINDALIAS_STAGED, bucketName1, bucketName2, bucketAlias)
            raise Exception('set replication failed, resp: %s' % replicationResp)

        return {'code': 'OK', 'message': 'create virtual bucket success', 'virtualBucketName': bucketAlias,
                'bucketName1': bucketName1, 'bucketName2': bucketName2}

    def _get_cluster_group_id(self, azResp):
        azJsonResp = util.jsonLoadsForPy2(azResp.body) if const.IS_PYTHON2 else json.loads(azResp.body)
        azInfos = azJsonResp.get('infos')

        if len(azInfos) != const.VIRTUAL_BUCKET_NEED_AZ_COUNT:
            raise Exception('the number of AZs does not meet the requirements')

        firstAZKey = next(iter(azInfos))
        firstAZValue = azInfos.get(firstAZKey)
        if len(firstAZValue) == 0:
            raise Exception('no cluster exists in the AZ, AZ key: %s' % firstAZKey)

        firstAZCgId = firstAZValue[0].get(const.KEY_CLUSTER_GROUP_ID)
        if not firstAZCgId:
            raise Exception('this AZs first cluster group id is None, AZ key: %s' % firstAZKey)

        secondAZKey = list(azInfos.keys())[-1]
        secondAZValue = azInfos.get(secondAZKey)
        if len(secondAZValue) == 0:
            raise Exception('no cluster exists in the AZ, AZ key: %s' % secondAZKey)

        secondAZCgId = secondAZValue[0].get(const.KEY_CLUSTER_GROUP_ID)
        if not secondAZCgId:
            raise Exception('this AZs first cluster group id is None, AZ key: %s' % secondAZKey)

        return firstAZCgId, secondAZCgId

    def _create_bucket_with_cluster_id(self, firstAZCgId, secondAZCgId, bucketName1, bucketName2, bucketAlias, header):
        # 判断桶是否存在
        bucket1CgId, bucket2CgId = self._head_virtual_bucket(bucketName1, bucketName2)

        # 两个桶都存在，且cluster group id一致
        if bucket1CgId and bucket2CgId and bucket1CgId == bucket2CgId:
            raise Exception('create bucket failed, both buckets exist and cluster group id is the same')

        extensionHeaders = ExtensionHeader()

        # 只存在桶1
        if bucket1CgId:
            extensionHeaders.locationClusterGroupId = secondAZCgId if bucket1CgId == firstAZCgId else firstAZCgId
            cbResp = self.createBucket(bucketName2, header=header, extensionHeaders=extensionHeaders)
            if cbResp.status != 200:
                self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED, bucketName1, bucketName2,
                                           bucketAlias)
                raise Exception('create bucket failed, cluster group id: %s, resp: %s' % (
                    extensionHeaders.locationClusterGroupId, cbResp))

        # 只存在桶2
        if bucket2CgId:
            extensionHeaders.locationClusterGroupId = secondAZCgId if bucket2CgId == firstAZCgId else firstAZCgId
            cbResp = self.createBucket(bucketName1, header=header, extensionHeaders=extensionHeaders)
            if cbResp.status != 200:
                self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED, bucketName1, bucketName2,
                                           bucketAlias)
                raise Exception('create bucket failed, cluster group id: %s, resp: %s' % (
                    extensionHeaders.locationClusterGroupId, cbResp))

        # 两个桶都不存在
        if not bucket1CgId and not bucket2CgId:
            extensionHeaders.locationClusterGroupId = firstAZCgId
            cbResp = self.createBucket(bucketName1, header=header, extensionHeaders=extensionHeaders)
            if cbResp.status != 200:
                self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED, bucketName1, bucketName2,
                                           bucketAlias)
                raise Exception('create bucket failed, cluster group id: %s, resp: %s' % (firstAZCgId, cbResp))

            extensionHeaders.locationClusterGroupId = secondAZCgId
            cbResp = self.createBucket(bucketName2, header=header, extensionHeaders=extensionHeaders)
            if cbResp.status != 200:
                self._clear_virtual_bucket(const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED, bucketName1, bucketName2,
                                           bucketAlias)
                raise Exception('create bucket failed, cluster group id: %s, resp: %s' % (secondAZCgId, cbResp))

    def _head_virtual_bucket(self, bucketName1, bucketName2):
        bucket1CgId = None
        bucket2CgId = None

        head1Resp = self.headBucket(bucketName1)
        if head1Resp.status == 200:
            for h in head1Resp.header:
                if const.LOCATION_CLUSTERGROUP_ID in h:
                    bucket1CgId = h[1]
                    break

        head2Resp = self.headBucket(bucketName2)
        if head2Resp.status == 200:
            for h in head2Resp.header:
                if const.LOCATION_CLUSTERGROUP_ID in h:
                    bucket2CgId = h[1]
                    break

        return bucket1CgId, bucket2CgId

    def _set_virtual_replication(self, agencyName, sourceBucketName, destBucketName):
        replication = Replication()
        replication.agency = agencyName

        # rule的默认规则如下：
        # id：{sourceBucketName}_to_{destBucketName}
        # prefix为空
        # status为Enabled
        # storageClass为STANDARD
        # deleteData为Enabled
        # historicalObjectReplication为Enabled
        _rules = []
        replicationRule = ReplicationRule()
        replicationRule.id = sourceBucketName + '_to_' + destBucketName
        replicationRule.prefix = ''
        replicationRule.status = 'Enabled'
        replicationRule.bucket = destBucketName
        replicationRule.storageClass = 'STANDARD'
        replicationRule.deleteData = 'Enabled'
        replicationRule.historicalObjectReplication = 'Enabled'

        _rules.append(replicationRule)
        replication.replicationRules = _rules
        resp = self.setBucketReplication(sourceBucketName, replication)
        return resp

    def _clear_virtual_bucket(self, staged, bucketName1, bucketName2, bucketAlias):
        # staged取值：
        # 1：创建真实桶
        # 2：创建桶别名
        # 3：绑定桶别名
        if staged >= const.VIRTUAL_BUCKET_BINDALIAS_STAGED:
            # 解绑桶别名
            unbindResp = self.unbindBucketAlias(bucketName1)
            if unbindResp.status != 204:
                raise Exception('unbind bucket alias failed, resp: %s' % unbindResp)

            unbindResp = self.unbindBucketAlias(bucketName2)
            if unbindResp.status != 204:
                raise Exception('unbind bucket alias failed, resp: %s' % unbindResp)

        if staged >= const.VIRTUAL_BUCKET_CREATEALIAS_STAGED:
            # 删除桶别名
            deleteAliasResp = self.deleteBucketAlias(bucketAlias)
            if deleteAliasResp.status != 204:
                raise Exception('delete bucket alias failed, resp: %s' % deleteAliasResp)

        if staged >= const.VIRTUAL_BUCKET_CREATEBUCKET_STAGED:
            # 删除真实桶
            deleteBucketResp = self.deleteBucket(bucketName1)
            if deleteBucketResp.status != 204:
                raise Exception('delete bucket failed, resp: %s' % deleteBucketResp)

            deleteBucketResp = self.deleteBucket(bucketName2)
            if deleteBucketResp.status != 204:
                raise Exception('delete bucket failed, resp: %s' % deleteBucketResp)

    # end virtual bucket related
    # end virtual bucket related
    # end virtual bucket related

    @funcCache
    def uploadFile(self, bucketName, objectKey, uploadFile, partSize=9 * 1024 * 1024,
                   taskNum=1, enableCheckpoint=False, checkpointFile=None,
                   checkSum=False, metadata=None, progressCallback=None, headers=None,
                   extensionHeaders=None, encoding_type=None):
        self.log_client.log(INFO, 'enter resume upload file...')
        self._assert_not_null(bucketName, 'bucketName is empty')
        self._assert_not_null(objectKey, 'objectKey is empty')
        self._assert_not_null(uploadFile, 'uploadFile is empty')

        return _resume_upload(bucketName, objectKey, uploadFile, partSize, taskNum, enableCheckpoint, checkpointFile,
                              checkSum, metadata, progressCallback, self, headers,
                              extensionHeaders=extensionHeaders, encoding_type=encoding_type)

    @funcCache
    def _downloadFileWithNotifier(self, bucketName, objectKey, downloadFile=None, partSize=5 * 1024 * 1024, taskNum=1,
                                  enableCheckpoint=False,
                                  checkpointFile=None, header=None, versionId=None, progressCallback=None,
                                  imageProcess=None, notifier=progress.NONE_NOTIFIER, extensionHeaders=None):
        self.log_client.log(INFO, 'enter resume download...')
        self._assert_not_null(bucketName, 'bucketName is empty')
        self._assert_not_null(objectKey, 'objectKey is empty')
        if header is None:
            header = GetObjectHeader()
        if downloadFile is None:
            downloadFile = objectKey

        return _resume_download(bucketName, objectKey, downloadFile, partSize, taskNum, enableCheckpoint,
                                checkpointFile, header, versionId, progressCallback, self,
                                imageProcess, notifier, extensionHeaders=extensionHeaders)

    def downloadFile(self, bucketName, objectKey, downloadFile=None, partSize=5 * 1024 * 1024, taskNum=1,
                     enableCheckpoint=False,
                     checkpointFile=None, header=None, versionId=None, progressCallback=None, imageProcess=None,
                     extensionHeaders=None):
        return self._downloadFileWithNotifier(bucketName, objectKey, downloadFile, partSize, taskNum, enableCheckpoint,
                                              checkpointFile, header, versionId, progressCallback, imageProcess,
                                              extensionHeaders=extensionHeaders)

    def downloadFiles(self, bucketName, prefix, downloadFolder=None, taskNum=const.DEFAULT_TASK_NUM,
                      taskQueueSize=const.DEFAULT_TASK_QUEUE_SIZE,
                      headers=None, imageProcess=None, interval=const.DEFAULT_BYTE_INTTERVAL,
                      taskCallback=None, progressCallback=None,
                      threshold=const.DEFAULT_MAXIMUM_SIZE, partSize=5 * 1024 * 1024, subTaskNum=1,
                      enableCheckpoint=False, checkpointFile=None, extensionHeaders=None):
        if headers is None:
            headers = GetObjectHeader()
        return _download_files(self, bucketName, prefix, downloadFolder, taskNum, taskQueueSize, headers, imageProcess,
                               interval, taskCallback, progressCallback, threshold, partSize, subTaskNum,
                               enableCheckpoint, checkpointFile, extensionHeaders=extensionHeaders)

    # OEF interface

    @funcCache
    def setBucketFetchPolicy(self, bucketName, status, agency, extensionHeaders=None):
        self._assert_not_null(status, "status is empty")
        self._assert_not_null(agency, "agency is empty")
        fetchPolicy = FetchPolicy(status, agency)
        return self._make_put_request(bucketName, const.FETCH_POLICY_KEY, extensionHeaders=extensionHeaders,
                                      **self.convertor.trans_set_bucket_fetch_policy(fetchPolicy))

    @funcCache
    def getBucketFetchPolicy(self, bucketName, extensionHeaders=None):
        headers = {self.ha.oef_marker_header(): "yes"}
        return self._make_get_request(bucketName, const.FETCH_POLICY_KEY, methodName="getBucketFetchPolicy",
                                      headers=headers, extensionHeaders=extensionHeaders)

    @funcCache
    def deleteBucketFetchPolicy(self, bucketName, extensionHeaders=None):
        headers = {self.ha.oef_marker_header(): "yes"}
        return self._make_delete_request(bucketName, const.FETCH_POLICY_KEY, headers=headers,
                                         extensionHeaders=extensionHeaders)

    @funcCache
    def setBucketFetchJob(self, bucketName, url, host=None, key=None, md5=None, callBackUrl=None,
                          callBackBody=None, callBackBodyType=None, callBackHost=None, fileType=None,
                          ignoreSameKey=False, objectHeaders=None, etag=None, trustName=None, extensionHeaders=None):
        self._assert_not_null(url, "url is empty")
        fetchJob = _FetchJob(url=url, host=host, bucket=bucketName, key=key, md5=md5, callBackUrl=callBackUrl,
                             callBackBody=callBackBody, callBackBodyType=callBackBodyType, callBackHost=callBackHost,
                             fileType=fileType, ignoreSameKey=ignoreSameKey, objectHeaders=objectHeaders, etag=etag,
                             trustName=trustName)
        return self._make_post_request(bucketName, const.FETCH_JOB_KEY, methodName="setBucketFetchJob",
                                       extensionHeaders=extensionHeaders,
                                       **self.convertor.trans_set_bucket_fetch_job(fetchJob))

    @funcCache
    def getBucketFetchJob(self, bucketName, jobId, extensionHeaders=None):
        self._assert_not_null(jobId, "jobId is empty")
        headers = {self.ha.oef_marker_header(): "yes"}
        key = const.FETCH_JOB_KEY + "/" + jobId
        return self._make_get_request(bucketName, key, methodName="getBucketFetchJob", headers=headers,
                                      extensionHeaders=extensionHeaders)


ObsClient.setBucketVersioningConfiguration = ObsClient.setBucketVersioning
ObsClient.getBucketVersioningConfiguration = ObsClient.getBucketVersioning
ObsClient.deleteBucketLifecycleConfiguration = ObsClient.deleteBucketLifecycle
ObsClient.setBucketLifecycleConfiguration = ObsClient.setBucketLifecycle
ObsClient.getBucketLifecycleConfiguration = ObsClient.getBucketLifecycle
ObsClient.getBucketWebsiteConfiguration = ObsClient.getBucketWebsite
ObsClient.setBucketWebsiteConfiguration = ObsClient.setBucketWebsite
ObsClient.deleteBucketWebsiteConfiguration = ObsClient.deleteBucketWebsite
ObsClient.setBucketLoggingConfiguration = ObsClient.setBucketLogging
ObsClient.getBucketLoggingConfiguration = ObsClient.getBucketLogging
