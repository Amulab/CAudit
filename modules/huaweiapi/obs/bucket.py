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


class BucketClient(object):
    allowedMethod = [
        'createBucket',
        'deleteBucket',
        'headBucket',
        'getBucketMetadata',
        'setBucketQuota',
        'getBucketQuota',
        'getBucketStorageInfo',
        'setBucketAcl',
        'getBucketAcl',
        'setBucketPolicy',
        'getBucketPolicy',
        'deleteBucketPolicy',
        'setBucketVersioning',
        'getBucketVersioning',
        'listVersions',
        'listObjects',
        'listMultipartUploads',
        'deleteBucketLifecycle',
        'setBucketLifecycle',
        'getBucketLifecycle',
        'deleteBucketWebsite',
        'setBucketWebsite',
        'getBucketWebsite',
        'setBucketLogging',
        'getBucketLogging',
        'getBucketLocation',
        'getBucketTagging',
        'setBucketTagging',
        'deleteBucketTagging',
        'setBucketCors',
        'deleteBucketCors',
        'getBucketCors',
        'setBucketNotification',
        'getBucketNotification',
        'getObjectMetadata',
        'setObjectMetadata',
        'getObject',
        'putContent',
        'putObject',
        'appendObject',
        'putFile',
        'uploadPart',
        'copyObject',
        'setObjectAcl',
        'getObjectAcl',
        'deleteObject',
        'deleteObjects',
        'restoreObject',
        'initiateMultipartUpload',
        'copyPart',
        'completeMultipartUpload',
        'abortMultipartUpload',
        'listParts',
        'getBucketStoragePolicy',
        'setBucketStoragePolicy',
        'optionsBucket',
        'optionsObject',
        'setBucketEncryption',
        'getBucketEncryption',
        'deleteBucketEncryption',
        'headObject',
        'setBucketRequestPayment',
        'getBucketRequestPayment',
        'setBucketFetchPolicy',
        'getBucketFetchPolicy',
        'deleteBucketFetchPolicy',
        'setBucketFetchJob',
        'getBucketFetchJob'
    ]

    def __init__(self, obsClient, bucketName):
        self.__obsClient = obsClient
        self.__bucketName = bucketName

    def __getattr__(self, key):
        if key in self.allowedMethod and hasattr(self.__obsClient, key):
            original_method = getattr(self.__obsClient, key)
            if callable(original_method):
                def delegate(*args, **kwargs):
                    _args = list(args)
                    if key == 'copyObject':
                        if 'destBucketName' not in kwargs:
                            if len(_args) >= 2:
                                _args.insert(2, self.__bucketName)
                            else:
                                kwargs['destBucketName'] = self.__bucketName
                    else:
                        if 'bucketName' not in kwargs:
                            _args.insert(0, self.__bucketName)
                    return original_method(*_args, **kwargs)

                return delegate
        return super(BucketClient, self).__getattribute__(key)
