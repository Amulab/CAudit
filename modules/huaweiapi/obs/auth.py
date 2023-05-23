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

import hashlib
import hmac
import binascii
from modules.huaweiapi.obs import util
from modules.huaweiapi.obs import const


class Authentication(object):

    def __init__(self, ak, sk, path_style, ha, server, is_cname):
        self.ak = ak
        self.sk = sk
        self.path_style = path_style
        self.ha = ha
        self.server = server
        self.is_cname = is_cname

    def doAuth(self, method, bucket, key, path_args, headers, expires=None):
        ret = self.getSignature(method, bucket, key, path_args, headers, expires)
        return {
            const.AUTHORIZATION_HEADER: '%s %s:%s' % (self.ha.auth_prefix(), self.ak, ret['Signature']),
            const.CANONICAL_STRING: ret[const.CANONICAL_STRING]
        }

    def getSignature(self, method, bucket, key, path_args, headers, expires=None):
        canonical_string = self.__make_canonical_string(method, bucket, key, path_args, headers, expires)
        return {
            'Signature': self.hmacSha128(canonical_string),
            const.CANONICAL_STRING: canonical_string
        }

    def hmacSha128(self, canonical_string):
        if const.IS_PYTHON2:
            hashed = hmac.new(self.sk, canonical_string, hashlib.sha1)
            encode_canonical = binascii.b2a_base64(hashed.digest())[:-1]
        else:
            hashed = hmac.new(self.sk.encode('UTF-8'), canonical_string.encode('UTF-8'), hashlib.sha1)
            encode_canonical = binascii.b2a_base64(hashed.digest())[:-1].decode('UTF-8')

        return encode_canonical

    def __make_canonical_string(self, method, bucket_name, key, path_args, headers, expires=None):
        interesting_headers = self.__make_canonicalstring_interesting_headers(headers, expires)
        key_list = sorted(interesting_headers.keys())
        str_list = self.__make_canonicalstring_str_list(key_list, method, interesting_headers)
        URI = ''
        _bucket_name = self.server if self.is_cname else bucket_name
        if _bucket_name:
            URI += '/'
            URI += _bucket_name
            if not self.path_style or self.is_cname:
                URI += '/'

        if key:
            if not URI.endswith('/'):
                URI += '/'
            URI += util.encode_object_key(key)

        if URI:
            str_list.append(URI)
        else:
            str_list.append('/')

        if path_args:
            e = '?'
            cannoList = sorted(path_args.items(), key=lambda d: d[0])
            for path_key, path_value in cannoList:
                if path_key.lower() in const.ALLOWED_RESOURCE_PARAMTER_NAMES or path_key.lower().startswith(
                        self.ha._get_header_prefix()):
                    path_key = util.encode_item(path_key, '/')
                    if path_value is None:
                        e += path_key + '&'
                        continue
                    e += path_key + '=' + util.to_string(path_value) + '&'

            e = e[:-1]
            str_list.append(e)
        return ''.join(str_list)

    def __make_canonicalstring_interesting_headers(self, headers, expires):
        interesting_headers = {}
        if isinstance(headers, dict):
            for hash_key in headers.keys():
                lk = hash_key.lower()
                if lk in const.CONTENT_LIST or lk.startswith(self.ha._get_header_prefix()):
                    s = headers.get(hash_key)
                    interesting_headers[lk] = ''.join(s)

        key_list = interesting_headers.keys()

        if self.ha.date_header() in key_list:
            interesting_headers[const.DATE_HEADER.lower()] = ''

        if expires:
            interesting_headers[const.DATE_HEADER.lower()] = expires

        if const.CONTENT_TYPE_HEADER.lower() not in key_list:
            interesting_headers[const.CONTENT_TYPE_HEADER.lower()] = ''

        if const.CONTENT_MD5_HEADER.lower() not in key_list:
            interesting_headers[const.CONTENT_MD5_HEADER.lower()] = ''

        return interesting_headers

    def __make_canonicalstring_str_list(self, keylist, method, interesting_headers):
        str_list = [method + '\n']
        for k in keylist:
            header_key = util.to_string(k)
            val = '' if interesting_headers[header_key] is None else interesting_headers[header_key]
            if header_key.startswith(self.ha._get_meta_header_prefix()):
                str_list.append(header_key + ':' + util.to_string(val).strip())
            elif header_key.startswith(self.ha._get_header_prefix()):
                str_list.append(header_key + ':' + val)
            else:
                str_list.append(val)
            str_list.append('\n')
        return str_list


class V4Authentication(object):
    CONTENT_SHA256 = 'UNSIGNED-PAYLOAD'

    def __init__(self, ak, sk, region, shortDate, longDate, path_style, ha):
        self.ak = ak
        self.sk = sk
        self.region = region
        self.shortDate = shortDate
        self.longDate = longDate
        self.path_style = path_style
        self.ha = ha

    def doAuth(self, method, bucket, key, args_path, headers):
        args_path = args_path if isinstance(args_path, dict) else {}
        headers = headers if isinstance(headers, dict) else {}
        headers[self.ha.content_sha256_header()] = self.CONTENT_SHA256

        credential = self.getCredential()
        headMap = self.setMapKeyLower(headers)
        signedHeaders = self.getSignedHeaders(headMap)
        ret = self.getSignature(method, bucket, key, args_path, headMap, signedHeaders)
        auth = 'AWS4-HMAC-SHA256 Credential=%s,SignedHeaders=%s,Signature=%s' % (
            credential, signedHeaders, ret['Signature'])
        return {
            const.AUTHORIZATION_HEADER: auth,
            const.CANONICAL_REQUEST: ret[const.CANONICAL_REQUEST]
        }

    def getCredential(self):
        return '%s/%s/%s/s3/aws4_request' % (self.ak, self.shortDate, self.region)

    def getScope(self):
        return '%s/%s/s3/aws4_request' % (self.shortDate, self.region)

    @staticmethod
    def getSignedHeaders(headMap):
        headList = sorted(headMap.items(), key=lambda d: d[0])
        signedHeaders = ''
        i = 0
        for val in headList:
            if i != 0:
                signedHeaders += ';'
            signedHeaders += val[0]
            i = 1
        return signedHeaders

    def getSignature(self, method, bucket, key, args_path, headMap, signedHeaders, payload=None):
        outPut = 'AWS4-HMAC-SHA256' + '\n'
        outPut += self.longDate + '\n'
        outPut += self.getScope() + '\n'
        cannonicalRequest = self.getCanonicalRequest(method, bucket, key, args_path, headMap, signedHeaders, payload)

        if const.IS_PYTHON2:
            stringToSign = outPut + self.__shaCannonicalRequest_python2(cannonicalRequest)
            signingKey = self.getSigningKey_python2()
        else:
            stringToSign = outPut + self.__shaCannonicalRequest_python3(cannonicalRequest)
            stringToSign = stringToSign.encode('UTF-8')
            signingKey = self.getSigningKey_python3()
        return {
            'Signature': self.hmacSha256(signingKey, stringToSign),
            const.CANONICAL_REQUEST: cannonicalRequest
        }

    @staticmethod
    def hmacSha256(signingKey, stringToSign):
        return hmac.new(signingKey, stringToSign, hashlib.sha256).hexdigest()

    def getSigningKey_python2(self):
        key = 'AWS4' + self.sk
        dateKey = hmac.new(key, self.shortDate, hashlib.sha256).digest()
        dateRegionKey = hmac.new(dateKey, self.region, hashlib.sha256).digest()
        dateRegionServiceKey = hmac.new(dateRegionKey, 's3', hashlib.sha256).digest()
        signingKey = hmac.new(dateRegionServiceKey, 'aws4_request', hashlib.sha256).digest()
        return signingKey

    def getSigningKey_python3(self):
        key = 'AWS4' + self.sk
        dateKey = hmac.new(key.encode('UTF-8'), self.shortDate.encode('UTF-8'), hashlib.sha256).digest()
        dateRegionKey = hmac.new(dateKey, self.region.encode('UTF-8'), hashlib.sha256).digest()
        dateRegionServiceKey = hmac.new(dateRegionKey, 's3'.encode('UTF-8'), hashlib.sha256).digest()
        signingKey = hmac.new(dateRegionServiceKey, 'aws4_request'.encode('UTF-8'), hashlib.sha256).digest()
        return signingKey

    def getCanonicalRequest(self, method, bucket, key, args_path, headMap, signedHeaders, payload=None):
        output = [method]
        output.append(self.getCanonicalURI(bucket, key))
        output.append(self.getCanonicalQueryString(args_path))
        output.append(self.getCanonicalHeaders(headMap))
        output.append(signedHeaders)
        output.append(self.CONTENT_SHA256 if payload is None else payload)
        return '\n'.join(output)

    @staticmethod
    def __shaCannonicalRequest_python2(cannonicalRequest):
        return hashlib.sha256(cannonicalRequest).hexdigest()

    @staticmethod
    def __shaCannonicalRequest_python3(cannonicalRequest):
        return hashlib.sha256(cannonicalRequest.encode('UTF-8')).hexdigest()

    def getCanonicalURI(self, bucket=None, key=None):
        URI = ''
        if self.path_style and bucket:
            URI += '/' + bucket
        if key:
            URI += '/' + key
        if not URI:
            URI = '/'
        return util.encode_object_key(URI)

    @staticmethod
    def getCanonicalQueryString(args_path):
        canonMap = {}
        for key, value in args_path.items():
            canonMap[key] = value
        cannoList = sorted(canonMap.items(), key=lambda d: d[0])
        queryStr = ''
        i = 0
        for val in cannoList:
            if i != 0:
                queryStr += '&'
            queryStr += '%s=%s' % (util.encode_item(val[0], '/'), util.encode_item(val[1], ''))
            i = 1
        return queryStr

    @staticmethod
    def getCanonicalHeaders(headMap):
        headList = sorted(headMap.items(), key=lambda d: d[0])
        canonicalHeaderStr = ''
        for val in headList:
            if isinstance(val[1], list):
                tlist = sorted(val[1])
                for v in tlist:
                    canonicalHeaderStr += val[0] + ':' + v + '\n'
            else:
                canonicalHeaderStr += val[0] + ':' + str(val[1]) + '\n'
        return canonicalHeaderStr

    @staticmethod
    def setMapKeyLower(inputMap):
        outputMap = {}
        for key in inputMap.keys():
            outputMap[key.lower()] = inputMap[key]
        return outputMap
