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
import hyper
from hyper.common import headers
from hyper.common import util
from hyper.http20 import stream
from hyper.common import exceptions
from modules.huaweiapi.obs import const
import threading


def _is_hyper_exception(e):
    return isinstance(e, (exceptions.SocketError, exceptions.InvalidResponseError, exceptions.ConnectionResetError))


def _get_server_connection(server, port=None, context=None, is_secure=False, proxy_host=None, proxy_port=None):
    try:
        return HTTP20ConnectionWrapper(host=server, port=port, ssl_context=context, secure=is_secure,
                                       proxy_host=proxy_host, proxy_port=proxy_port)
    except Exception as e:
        raise e


def to_string(item):
    try:
        return str(item) if item is not None else ''
    except Exception:
        return ''


def _get_ssl_context(ssl_verify):
    try:
        from hyper import tls
        import ssl
        import os
        context = tls.init_context(None, None, None)
        context.check_hostname = False
        if ssl_verify:
            cafile = to_string(ssl_verify)
            if os.path.isfile(cafile):
                context.load_verify_locations(cafile)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_NONE
        return context
    except Exception:
        import traceback
        print(traceback.format_exc())


def canonical_form(k, v):
    yield k, v


headers.canonical_form = canonical_form


def _send_chunk(self, data, final):
    while len(data) > self._out_flow_control_window:
        self._recv_cb()

    end_stream = False
    if len(data) <= stream.MAX_CHUNK and final:
        end_stream = True

    with self._conn as conn:
        conn.send_data(
            stream_id=self.stream_id, data=data, end_stream=end_stream
        )
    self._send_outstanding_data()

    if end_stream:
        self.local_closed = True


def send_data(self, data, final):
    chunks = [data[i:i + stream.MAX_CHUNK]
              for i in range(0, len(data), stream.MAX_CHUNK)]

    index = 0
    count = len(chunks)
    for chunk in chunks:
        self._send_chunk(chunk, final and index == count - 1)
        index += 1


stream.Stream._send_chunk = _send_chunk
stream.Stream.send_data = send_data


class HTTP20ConnectionWrapper(hyper.HTTP20Connection):

    def __init__(self, host, port=None, secure=None, window_manager=None,
                 enable_push=False, ssl_context=None, proxy_host=None,
                 proxy_port=None, force_proto=None, **kwargs):
        self._stream_id_context = threading.local()
        super(HTTP20ConnectionWrapper, self).__init__(host, port=port, secure=secure,
                                                      window_manager=window_manager, enable_push=enable_push,
                                                      ssl_context=ssl_context, proxy_host=proxy_host,
                                                      proxy_port=proxy_port, force_proto=force_proto, **kwargs)

    def getresponse(self, stream_id=None):
        stream_id = stream_id or (
            self._stream_id_context.stream_id if hasattr(self._stream_id_context, 'stream_id') else None)
        stream = self._get_stream(stream_id)
        return HTTP20ResponseWrapper(stream.getheaders(), stream)

    def request(self, method, url, body=None, headers=None):
        headers = headers or {}
        if const.HOST_HEADER in headers:
            headers[':authority'] = headers[const.HOST_HEADER]

        with self._write_lock:
            stream_id = self.putrequest(method, url)
            self._stream_id_context.stream_id = stream_id
            default_headers = (':method', ':scheme', ':authority', ':path')
            for name, value in headers.items():
                is_default = util.to_native_string(name) in default_headers
                if isinstance(value, list):
                    for item in value:
                        self.putheader(name, item, stream_id, replace=is_default)
                else:
                    self.putheader(name, value, stream_id, replace=is_default)

            final = True
            message_body = body
            if body is not None:
                if callable(body):
                    final = False
                    message_body = None
                else:
                    if isinstance(body, (unicode, bytes)):
                        message_body = util.to_bytestring(body)
                    if len(message_body) == 0:
                        message_body = None

            self.endheaders(message_body=message_body, final=final, stream_id=stream_id)
            if not final:
                body(self)

            return stream_id

    def send(self, data, final=False, stream_id=None):
        stream_id = stream_id or (
            self._stream_id_context.stream_id if hasattr(self._stream_id_context, 'stream_id') else None)
        stream = self._get_stream(stream_id)
        stream.send_data(data, final)


class HTTP20ResponseWrapper(hyper.HTTP20Response):
    def getheader(self, key, default_value=None):
        ret = self.headers.get(key)
        return ret if ret is not None else default_value

    def getheaders(self):
        return self.headers
