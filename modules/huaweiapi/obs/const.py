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

import sys
import platform
import os

READ_ONCE_LENGTH = 65536

CONTENT_LENGTH_HEADER = 'Content-Length'
CONTENT_TYPE_HEADER = 'Content-Type'
CONTENT_MD5_HEADER = 'Content-MD5'
CACHE_CONTROL_HEADER = 'Cache-Control'
CONTENT_DISPOSITION_HEADER = 'Content-Disposition'
CONTENT_ENCODING_HEADER = 'Content-Encoding'
CONTENT_LANGUAGE_HEADER = 'Content-Language'
EXPIRES_HEADER = 'Expires'
DATE_HEADER = 'Date'

CONTENT_LIST = [CONTENT_TYPE_HEADER.lower(), CONTENT_MD5_HEADER.lower(), DATE_HEADER.lower()]

HOST_HEADER = 'Host'
AUTHORIZATION_HEADER = 'Authorization'
CONNECTION_HEADER = 'Connection'
PROXY_CONNECTION_HEADER = 'Proxy-Connection'
PROXY_AUTHORIZATION_HEADER = 'Proxy-Authorization'
USER_AGENT_HEADER = 'User-Agent'
TRANSFER_ENCODING_HEADER = 'Transfer-Encoding'
TRANSFER_ENCODING_VALUE = 'chunked'
ORIGIN_HEADER = 'Origin'
RANGE_HEADER = 'Range'
IF_MODIFIED_SINCE = 'If-Modified-Since'
IF_UNMODIFIED_SINCE = 'If-Unmodified-Since'
IF_MATCH = 'If-Match'
IF_NONE_MATCH = 'If-None-Match'

CONNECTION_KEEP_ALIVE_VALUE = 'Keep-Alive'
CONNECTION_CLOSE_VALUE = 'close'
ACCESS_CONTROL_REQUEST_METHOD_HEADER = 'Access-Control-Request-Method'
ACCESS_CONTROL_REQUEST_HEADERS_HEADER = 'Access-Control-Request-Headers'
LOCATION_HEADER = 'Location'
ETAG_HEADER = 'ETag'
LAST_MODIFIED_HEADER = 'Last-Modified'

LOCATION_CLUSTERGROUP_ID = 'location-clustergroup-id'
X_AUTH_TOKEN_HEADER = 'X-Auth-Token'
KEY_CLUSTER_GROUP_ID = 'cgId'
VIRTUAL_BUCKET_NEED_AZ_COUNT = 2
VIRTUAL_BUCKET_CREATEBUCKET_STAGED = 1
VIRTUAL_BUCKET_CREATEALIAS_STAGED = 2
VIRTUAL_BUCKET_BINDALIAS_STAGED = 3

VERSION_ID_PARAM = 'versionId'
RESPONSE_CACHE_CONTROL_PARAM = 'response-cache-control'
RESPONSE_CONTENT_DISPOSITION_PARAM = 'response-content-disposition'
RESPONSE_CONTENT_ENCODING_PARAM = 'response-content-encoding'
RESPONSE_CONTENT_LANGUAGE_PARAM = 'response-content-language'
RESPONSE_CONTENT_TYPE_PARAM = 'response-content-type'
RESPONSE_EXPIRES_PARAM = 'response-expires'
X_IMAGE_PROCESS_PARAM = 'x-image-process'
OBSALIAS_PARAM = 'obsalias'
OBSBUCKETALIAS_PARAM = 'obsbucketalias'

HTTP_METHOD_PUT = 'PUT'
HTTP_METHOD_POST = 'POST'
HTTP_METHOD_GET = 'GET'
HTTP_METHOD_DELETE = 'DELETE'
HTTP_METHOD_HEAD = 'HEAD'
HTTP_METHOD_OPTIONS = 'OPTIONS'

IS_WINDOWS = platform.system() == 'Windows' or os.name == 'nt'
IS_PYTHON2 = sys.version_info.major == 2 or sys.version < '3'
IS_PYTHON35_UP = sys.version >= '3.5'
BASESTRING = basestring if IS_PYTHON2 else str
UNICODE = unicode if IS_PYTHON2 else str
LONG = long if IS_PYTHON2 else int

DEFAULT_SECURE_PORT = 443
DEFAULT_INSECURE_PORT = 80
DEFAULT_MINIMUM_SIZE = 100 * 1024
DEFAULT_MAXIMUM_SIZE = 5 * 1024 * 1024 * 1024

DEFAULT_BYTE_INTTERVAL = 102400
DEFAULT_TASK_INTTERVAL = 100
DEFAULT_TASK_NUM = 8
DEFAULT_TASK_QUEUE_SIZE = 20000

OBS_SDK_VERSION = '3.21.12'

V2_META_HEADER_PREFIX = 'x-amz-meta-'
V2_HEADER_PREFIX = 'x-amz-'

OBS_META_HEADER_PREFIX = 'x-obs-meta-'
OBS_HEADER_PREFIX = 'x-obs-'

GMT_DATE_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
LONG_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
SHORT_DATE_FORMAT = '%Y%m%d'
EXPIRATION_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

CANONICAL_REQUEST = 'CannonicalRequest'
CANONICAL_STRING = 'CanonicalString'

IPv4_REGEX = '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'

V2_SIGNATURE = 'v2'
OBS_SIGNATURE = 'obs'

FETCH_POLICY_KEY = "v1/extension_policy"
FETCH_JOB_KEY = "v1/async-fetch/jobs"

WORKFLOW_TEMPLATES = 'workflowtemplates'
WORKFLOWS = 'workflows'
WORKFLOW_EXECUTIONS = 'workflowexecutions'
WORKFLOW_TRIGGERPOLICY = 'obsworkflowtriggerpolicy'

ALLOWED_RESOURCE_PARAMTER_NAMES = (
    'acl',
    'backtosource',
    'policy',
    'torrent',
    'logging',
    'location',
    'storageinfo',
    'quota',
    'storageclass',
    'storagepolicy',
    'requestpayment',
    'versions',
    'versioning',
    'versionid',
    'uploads',
    'uploadid',
    'partnumber',
    'website',
    'notification',
    'lifecycle',
    'deletebucket',
    'delete',
    'cors',
    'restore',
    'tagging',
    'replication',
    'metadata',
    'encryption',

    # File System API
    'append',
    'position',
    'truncate',
    'modify',
    'rename',
    'length',
    'name',
    'fileinterface',

    'response-content-type',
    'response-content-language',
    'response-expires',
    'response-cache-control',
    'response-content-disposition',
    'response-content-encoding',
    'x-image-save-bucket',
    'x-image-save-object',
    'x-image-process',
    'x-oss-process',

    # workflow api
    'x-workflow-prefix',
    'x-workflow-start',
    'x-workflow-limit',
    'x-workflow-template-name',
    'x-workflow-graph-name',
    'x-workflow-execution-state',
    'x-workflow-execution-type',
    'x-workflow-next-marker',
    'obsworkflowtriggerpolicy',

    # virtual bucket api
    'obsbucketalias',
    'obsalias'
)

ALLOWED_REQUEST_HTTP_HEADER_METADATA_NAMES = (
    'content-type',
    'content-md5',
    'content-length',
    'content-language',
    'expires',
    'origin',
    'cache-control',
    'content-disposition',
    'content-encoding',
    'access-control-request-method',
    'access-control-request-headers',
    'success-action-redirect',
    'x-default-storage-class',
    'location',
    'date',
    'etag',
    'range',
    'host',
    'if-modified-since',
    'if-unmodified-since',
    'if-match',
    'if-none-match',
    'last-modified',
    'content-range',
    'x-auth-token'
)

ALLOWED_RESPONSE_HTTP_HEADER_METADATA_NAMES = (
    'content-type',
    'content-md5',
    'content-length',
    'content-language',
    'expires',
    'origin',
    'cache-control',
    'content-disposition',
    'content-encoding',
    'x-default-storage-class',
    'location',
    'date',
    'etag',
    'host',
    'last-modified',
    'content-range',
    'x-reserved',
    'access-control-allow-origin',
    'access-control-allow-headers',
    'access-control-max-age',
    'access-control-allow-methods',
    'access-control-expose-headers',
    'connection',
    'x-reserved-indicator',
    'x-oef-request-id'
)

MIME_TYPES = {
    '7z': 'application/x-7z-compressed',
    'aac': 'audio/x-aac',
    'ai': 'application/postscript',
    'aif': 'audio/x-aiff',
    'apk': 'application/vnd.android.package-archive',
    'asc': 'text/plain',
    'asf': 'video/x-ms-asf',
    'atom': 'application/atom+xml',
    'avi': 'video/x-msvideo',
    'bmp': 'image/bmp',
    'bz2': 'application/x-bzip2',
    'cer': 'application/pkix-cert',
    'crl': 'application/pkix-crl',
    'crt': 'application/x-x509-ca-cert',
    'css': 'text/css',
    'csv': 'text/csv',
    'cu': 'application/cu-seeme',
    'deb': 'application/x-debian-package',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'dvi': 'application/x-dvi',
    'eot': 'application/vnd.ms-fontobject',
    'eps': 'application/postscript',
    'epub': 'application/epub+zip',
    'etx': 'text/x-setext',
    'flac': 'audio/flac',
    'flv': 'video/x-flv',
    'gif': 'image/gif',
    'gz': 'application/gzip',
    'htm': 'text/html',
    'html': 'text/html',
    'ico': 'image/x-icon',
    'ics': 'text/calendar',
    'ini': 'text/plain',
    'iso': 'application/x-iso9660-image',
    'jar': 'application/java-archive',
    'jpe': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'jpg': 'image/jpeg',
    'js': 'text/javascript',
    'json': 'application/json',
    'latex': 'application/x-latex',
    'log': 'text/plain',
    'm4a': 'audio/mp4',
    'm4v': 'video/mp4',
    'mid': 'audio/midi',
    'midi': 'audio/midi',
    'mov': 'video/quicktime',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4',
    'mp4a': 'audio/mp4',
    'mp4v': 'video/mp4',
    'mpe': 'video/mpeg',
    'mpeg': 'video/mpeg',
    'mpg': 'video/mpeg',
    'mpg4': 'video/mp4',
    'oga': 'audio/ogg',
    'ogg': 'audio/ogg',
    'ogv': 'video/ogg',
    'ogx': 'application/ogg',
    'pbm': 'image/x-portable-bitmap',
    'pdf': 'application/pdf',
    'pgm': 'image/x-portable-graymap',
    'png': 'image/png',
    'pnm': 'image/x-portable-anymap',
    'ppm': 'image/x-portable-pixmap',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'ps': 'application/postscript',
    'qt': 'video/quicktime',
    'rar': 'application/x-rar-compressed',
    'ras': 'image/x-cmu-raster',
    'rss': 'application/rss+xml',
    'rtf': 'application/rtf',
    'sgm': 'text/sgml',
    'sgml': 'text/sgml',
    'svg': 'image/svg+xml',
    'swf': 'application/x-shockwave-flash',
    'tar': 'application/x-tar',
    'tif': 'image/tiff',
    'tiff': 'image/tiff',
    'torrent': 'application/x-bittorrent',
    'ttf': 'application/x-font-ttf',
    'txt': 'text/plain',
    'wav': 'audio/x-wav',
    'webm': 'video/webm',
    'wma': 'audio/x-ms-wma',
    'wmv': 'video/x-ms-wmv',
    'woff': 'application/x-font-woff',
    'wsdl': 'application/wsdl+xml',
    'xbm': 'image/x-xbitmap',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xml': 'application/xml',
    'xpm': 'image/x-xpixmap',
    'xwd': 'image/x-xwindowdump',
    'yaml': 'text/yaml',
    'yml': 'text/yaml',
    'zip': 'application/zip'
}
