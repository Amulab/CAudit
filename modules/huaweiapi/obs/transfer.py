#!/usr/bin/python
# -*- coding:utf-8 -*-
# Copyright 2019 Huawei Technologies Co.,Ltd.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.  You may obtain a copy of the
# License at

# http://www.apache.org/licenses/LICENSE-2.0

import functools
import json
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
import math
import operator
import os
import sys
import threading
import traceback

from modules.huaweiapi.obs import const, progress, util
from modules.huaweiapi.obs.ilog import DEBUG, ERROR, INFO
from modules.huaweiapi.obs.model import BaseModel, CompleteMultipartUploadRequest, CompletePart, GetObjectHeader, GetObjectRequest, \
    UploadFileHeader

if const.IS_PYTHON2:
    import Queue as queue
else:
    import queue


def _resume_upload(bucketName, objectKey, uploadFile, partSize, taskNum, enableCheckPoint, checkPointFile, checkSum,
                   metadata, progressCallback, obsClient, headers, extensionHeaders=None, encoding_type=None):
    upload_operation = uploadOperation(util.to_string(bucketName), util.to_string(objectKey),
                                       util.to_string(uploadFile), partSize, taskNum, enableCheckPoint,
                                       util.to_string(checkPointFile), checkSum, metadata, progressCallback, obsClient,
                                       headers, extensionHeaders=extensionHeaders, encoding_type=encoding_type)
    return upload_operation._upload()


def _resume_download(bucketName, objectKey, downloadFile, partSize, taskNum, enableCheckPoint, checkPointFile,
                     header, versionId, progressCallback, obsClient, imageProcess=None,
                     notifier=progress.NONE_NOTIFIER, extensionHeaders=None):
    down_operation = downloadOperation(util.to_string(bucketName), util.to_string(objectKey),
                                       util.to_string(downloadFile), partSize, taskNum, enableCheckPoint,
                                       util.to_string(checkPointFile),
                                       header, versionId, progressCallback, obsClient, imageProcess, notifier,
                                       extensionHeaders=extensionHeaders)

    return _resume_download_with_operation(down_operation)


def _resume_download_with_operation(down_operation):
    if down_operation.size == 0:
        down_operation._delete_record()
        down_operation._delete_tmp_file()
        with open(down_operation.fileName, 'wb'):
            pass
        if down_operation.progressCallback is not None and callable(down_operation.progressCallback):
            down_operation.progressCallback(0, 0, 0)
        return down_operation._metadata_resp
    return down_operation._download()


class Operation(object):
    def __init__(self, bucketName, objectKey, fileName, partSize, taskNum, enableCheckPoint, checkPointFile,
                 progressCallback, obsClient, notifier=progress.NONE_NOTIFIER):
        self.bucketName = bucketName
        self.objectKey = objectKey
        self.fileName = util.safe_trans_to_gb2312(fileName)
        self.partSize = partSize
        self.taskNum = taskNum
        self.enableCheckPoint = enableCheckPoint
        self.checkPointFile = util.safe_trans_to_gb2312(checkPointFile)
        self.progressCallback = progressCallback
        self.notifier = notifier
        self.obsClient = obsClient
        self._lock = threading.Lock()
        self._abortLock = threading.Lock()
        self._abort = False
        self._record = None
        self._exception = None

    def _is_abort(self):
        with self._abortLock:
            return self._abort

    def _do_abort(self, error):
        with self._abortLock:
            self._abort = True
            if self._exception is None:
                self._exception = error

    def _get_record(self):
        self.obsClient.log_client.log(INFO, 'load checkpoint file...')
        if os.path.exists(self.checkPointFile):
            try:
                with open(self.checkPointFile, 'r') as f:
                    content = json.load(f)
                    return _parse_string(content)
            except ValueError:
                pass
        return None

    def _delete_record(self):
        if os.path.exists(self.checkPointFile):
            os.remove(self.checkPointFile)
            self.obsClient.log_client.log(INFO,
                                          'delete checkpoint file success. path is:{0}'.format(self.checkPointFile))

    def _write_record(self, record):
        with open(self.checkPointFile, 'w') as f:
            json.dump(record, f)
            self.obsClient.log_client.log(INFO,
                                          'write checkpoint file success. file path is {0}'.format(self.checkPointFile))


class uploadOperation(Operation):
    def __init__(self, bucketName, objectKey, uploadFile, partSize, taskNum, enableCheckPoint, checkPointFile,
                 checkSum, metadata, progressCallback, obsClient, headers, extensionHeaders=None, encoding_type=None):
        if enableCheckPoint and not checkPointFile:
            checkPointFile = uploadFile + '.upload_record'
        super(uploadOperation, self).__init__(bucketName, objectKey, uploadFile, partSize, taskNum, enableCheckPoint,
                                              checkPointFile, progressCallback, obsClient)
        self.checkSum = checkSum
        self.metadata = metadata
        self.headers = headers
        self.extensionHeaders = extensionHeaders
        self.encoding_type = encoding_type

        try:
            self.size = os.path.getsize(self.fileName)
            self.lastModified = os.path.getmtime(self.fileName)
        except Exception as e:
            self._delete_record()
            self.obsClient.log_client.log(ERROR,
                                          'something is happened when obtain uploadFile information. Please check')
            raise e
        self.total_parts = 0
        self.reset_partSize()
        self._record = {'bucketName': self.bucketName, 'objectKey': self.objectKey, 'uploadFile': self.fileName,
                        'partEtags': []}
        resp = self.obsClient.headBucket(self.bucketName, extensionHeaders=extensionHeaders)
        if resp.status > 300:
            raise Exception('head bucket {0} failed. Please check. Status:{1}.'.format(self.bucketName, resp.status))

    def reset_partSize(self):
        if self.partSize < const.DEFAULT_MINIMUM_SIZE:
            self.partSize = const.DEFAULT_MINIMUM_SIZE
        elif self.partSize > const.DEFAULT_MAXIMUM_SIZE:
            self.partSize = const.DEFAULT_MAXIMUM_SIZE
        else:
            self.partSize = util.to_int(self.partSize)
        if self.taskNum <= 0:
            self.taskNum = 1
        else:
            self.taskNum = int(math.ceil(self.taskNum))
        self.total_parts = int(self.size / self.partSize)
        if self.total_parts >= 10000:
            self.partSize = int(self.size / 10000) if self.size % 10000 == 0 else int(self.size / 10000) + 1
            self.total_parts = int(self.size / self.partSize)
        if self.size % self.partSize != 0:
            self.total_parts += 1

    def _upload(self):
        if self.headers is None:
            self.headers = UploadFileHeader()

        if self.enableCheckPoint:
            self._load()

        if "uploadId" not in self._record:
            self._prepare()

        unfinished_upload_parts = []
        sent_bytes = const.LONG(0)
        for p in self._record['uploadParts']:
            if not p['isCompleted']:
                unfinished_upload_parts.append(p)
            else:
                sent_bytes += p['length']

        if self.progressCallback is not None:
            self.notifier = progress.ProgressNotifier(self.progressCallback, self.size)
            self.notifier.start()

        try:
            if len(unfinished_upload_parts) > 0:

                if (self.size - sent_bytes) > 0:
                    self.notifier.send(sent_bytes)

                thread_pools = _ThreadPool(functools.partial(self._produce, upload_parts=unfinished_upload_parts),
                                           [self._consume] * self.taskNum)
                thread_pools.run()

                if self._abort:
                    self.obsClient.abortMultipartUpload(self.bucketName, self.objectKey, self._record['uploadId'],
                                                        extensionHeaders=self.extensionHeaders)
                    self.obsClient.log_client.log(
                        ERROR,
                        'the code from server is 4**, please check space, permission and so on.'
                    )
                    self._delete_record()
                    if self._exception is not None:
                        raise Exception(self._exception)

                for p in self._record['uploadParts']:
                    if not p['isCompleted']:
                        if not self.enableCheckPoint:
                            self.obsClient.abortMultipartUpload(self.bucketName, self.objectKey,
                                                                self._record['uploadId'],
                                                                extensionHeaders=self.extensionHeaders)
                        raise Exception('some parts are failed when upload. Please try again')

            part_Etags = []
            for part in self._record['partEtags']:
                part_Etags.append(CompletePart(partNum=part['partNum'], etag=part['etag']))
                self.obsClient.log_client.log(INFO, 'Completing to upload multi_parts')
            resp = self.obsClient.completeMultipartUpload(self.bucketName, self.objectKey, self._record['uploadId'],
                                                          CompleteMultipartUploadRequest(part_Etags),
                                                          extensionHeaders=self.extensionHeaders,
                                                          encoding_type=self.encoding_type)
            self._upload_handle_response(resp)
            return resp
        finally:
            self.notifier.end()

    def _upload_handle_response(self, resp):
        if resp.status < 300:
            if self.enableCheckPoint:
                self._delete_record()
        else:
            if not self.enableCheckPoint:
                self.obsClient.abortMultipartUpload(self.bucketName, self.objectKey, self._record['uploadId'],
                                                    extensionHeaders=self.extensionHeaders)
                self.obsClient.log_client.log(
                    ERROR,
                    'something is wrong when complete multipart.ErrorCode:{0}. ErrorMessage:{1}'.format(
                        resp.errorCode, resp.errorMessage))
            else:
                if 300 < resp.status < 500:
                    self.obsClient.abortMultipartUpload(self.bucketName, self.objectKey, self._record['uploadId'],
                                                        extensionHeaders=self.extensionHeaders)
                    self.obsClient.log_client.log(
                        ERROR,
                        'something is wrong when complete multipart.ErrorCode:{0}. ErrorMessage:{1}'.format(
                            resp.errorCode, resp.errorMessage))
                    self._delete_record()

    def _load(self):
        self._record = self._get_record()
        if self._record and not (self._type_check(self._record) and self._check_upload_record(self._record)):
            if self._record['bucketName'] and self._record['objectKey'] and self._record['uploadId'] is not None:
                self.obsClient.abortMultipartUpload(self._record['bucketName'], self._record['objectKey'],
                                                    self._record['uploadId'], extensionHeaders=self.extensionHeaders)
            self.obsClient.log_client.log(ERROR, 'checkpointFile is invalid')
            self._delete_record()
            self._record = None
        if self._record is None:
            self._record = {'bucketName': self.bucketName, 'objectKey': self.objectKey, 'uploadFile': self.fileName,
                            'partEtags': []}

    def _type_check(self, record):
        try:
            for key in ('bucketName', 'objectKey', 'uploadId', 'uploadFile'):
                if not isinstance(record[key], str):
                    self.obsClient.log_client.log(
                        ERROR,
                        '{0} is not a string type. {1} belong to {2}'.format(key, record[key], record[key].__class__)
                    )
                    return False
            if not isinstance(record['fileStatus'], list):
                self.obsClient.log_client.log(ERROR, 'fileStatus is not a list.It is {0} type'.format(
                    record['fileStatus'].__class__))
                return False
            if not isinstance(record['uploadParts'], list):
                self.obsClient.log_client.log(ERROR, 'uploadParts is not a list.It is {0} type'.format(
                    record['uploadParts'].__class__))
                return False
            if not isinstance(record['partEtags'], list):
                self.obsClient.log_client.log(ERROR, 'partEtags is not a dict.It is {0} type'.format(
                    record['partEtags'].__class__))
                return False
        except KeyError as e:
            self.obsClient.log_client.log(INFO, 'Key is not found:{0}'.format(e.args))
            return False
        return True

    def _check_upload_record(self, record):
        if not ((record['bucketName'] == self.bucketName) and (record['objectKey'] == self.objectKey) and (
                record['uploadFile'] == self.fileName)):
            self.obsClient.log_client.log(INFO,
                                          'the bucketName or objectKey or uploadFile was changed. clear the record')
            return False
        if record['uploadId'] is None:
            self.obsClient.log_client.log(INFO,
                                          '{0} (uploadId) not exist, clear the record.'.format(record['upload_id']))
            return False

        if record['fileStatus'][0] != self.size or record['fileStatus'][1] != self.lastModified:
            self.obsClient.log_client.log(INFO, '{0} was changed, clear the record.'.format(self.fileName))
            return False
        if self.checkSum and len(record['fileStatus']) >= 3:
            checkSum = util.base64_encode(
                util.md5_file_encode_by_size_offset(file_path=self.fileName, size=self.size, offset=0))
            if record['fileStatus'][2] and record['fileStatus'][2] != checkSum:
                self.obsClient.log_client.log(INFO, '{0} content was changed, clear the record.'.format(self.fileName))
                return False
        return True

    def _slice_file(self):
        uploadParts = []

        if self.total_parts == 0:
            part = Part(util.to_long(1), util.to_long(0), util.to_long(0), False)
            uploadParts.append(part)
        else:
            offset = 0
            for i in range(1, self.total_parts + 1, 1):
                part = Part(util.to_long(i), util.to_long(offset), util.to_long(self.partSize), False)
                offset += self.partSize
                uploadParts.append(part)

            if self.size % self.partSize != 0:
                uploadParts[self.total_parts - 1].length = util.to_long(self.size % self.partSize)

        return uploadParts

    def get_init_upload_result(self):
        return self.obsClient.initiateMultipartUpload(self.bucketName, self.objectKey, metadata=self.metadata,
                                                      acl=self.headers.acl,
                                                      storageClass=self.headers.storageClass,
                                                      websiteRedirectLocation=self.headers.websiteRedirectLocation,
                                                      contentType=self.headers.contentType,
                                                      sseHeader=self.headers.sseHeader, expires=self.headers.expires,
                                                      extensionGrants=self.headers.extensionGrants,
                                                      extensionHeaders=self.extensionHeaders,
                                                      encoding_type=self.encoding_type)

    def _prepare(self):
        fileStatus = [self.size, self.lastModified]
        if self.checkSum:
            fileStatus.append(util.base64_encode(util.md5_file_encode_by_size_offset(self.fileName, self.size, 0)))

        resp = self.get_init_upload_result()

        if resp.status > 300:
            raise Exception('initiateMultipartUpload failed. ErrorCode:{0}. ErrorMessage:{1}'.format(resp.errorCode,
                                                                                                     resp.errorMessage))
        uploadId = resp.body.uploadId
        self._record["uploadParts"] = self._slice_file()
        self._record["uploadId"] = uploadId
        self._record["fileStatus"] = fileStatus
        self.obsClient.log_client.log(INFO, 'prepare new upload task success. uploadId = {0}'.format(uploadId))
        if self.enableCheckPoint:
            self._write_record(self._record)

    @staticmethod
    def _produce(ThreadPool, upload_parts):
        for part in upload_parts:
            ThreadPool.put(part)

    def _consume(self, ThreadPool):
        while ThreadPool.ok():
            part = ThreadPool.get()
            if part is None:
                break
            self._upload_part(part)

    def _upload_part(self, part):
        if not self._is_abort():
            try:
                resp = self.get_upload_part_resp(part)
                if resp.status < 300:
                    self._record['uploadParts'][part['partNumber'] - 1]['isCompleted'] = True
                    self._record['partEtags'].append(CompletePart(util.to_int(part['partNumber']), resp.body.etag))
                    if self.enableCheckPoint:
                        with self._lock:
                            self._write_record(self._record)
                else:
                    if 300 < resp.status < 500:
                        self._do_abort('errorCode:{0}, errorMessage:{1}'.format(resp.errorCode, resp.errorMessage))
                    self.obsClient.log_client.log(
                        ERROR,
                        'response from server is something wrong. ErrorCode:{0}, ErrorMessage:{1}'.format(
                            resp.errorCode, resp.errorMessage))
            except Exception as e:
                self.obsClient.log_client.log(DEBUG, 'upload part %s error, %s' % (part['partNumber'], e))
                self.obsClient.log_client.log(ERROR, traceback.format_exc())

    def get_upload_part_resp(self, part):
        return self.obsClient._uploadPartWithNotifier(self.bucketName, self.objectKey, part['partNumber'],
                                                      self._record['uploadId'], self.fileName,
                                                      isFile=True, partSize=part['length'],
                                                      offset=part['offset'], notifier=self.notifier,
                                                      extensionHeaders=self.extensionHeaders,
                                                      sseHeader=self.headers.sseHeader)


class downloadOperation(Operation):
    def __init__(self, bucketName, objectKey, downloadFile, partSize, taskNum, enableCheckPoint, checkPointFile,
                 header, versionId, progressCallback, obsClient, imageProcess=None, notifier=progress.NONE_NOTIFIER,
                 extensionHeaders=None):
        if enableCheckPoint and not checkPointFile:
            checkPointFile = downloadFile + '.download_record'
        super(downloadOperation, self).__init__(bucketName, objectKey, downloadFile, partSize, taskNum,
                                                enableCheckPoint,
                                                checkPointFile, progressCallback, obsClient, notifier)
        self.header = header
        self.versionId = versionId
        self.imageProcess = imageProcess
        self.extensionHeaders = extensionHeaders
        self._record = {'bucketName': self.bucketName, 'objectKey': self.objectKey, 'versionId': self.versionId,
                        'downloadFile': self.fileName, 'imageProcess': self.imageProcess}

        parent_dir = os.path.dirname(self.fileName)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir)

        self._tmp_file = self.fileName + '.tmp'
        metadata_resp = self.obsClient.getObjectMetadata(self.bucketName, self.objectKey, self.versionId,
                                                         extensionHeaders=self.extensionHeaders,
                                                         sseHeader=self.header.sseHeader, origin=self.header.origin,
                                                         requestHeaders=self.header.requestHeaders)
        if metadata_resp.status < 300:
            self.lastModified = metadata_resp.body.lastModified
            self.size = metadata_resp.body.contentLength \
                if metadata_resp.body.contentLength is not None and metadata_resp.body.contentLength >= 0 else 0
        else:
            if 400 <= metadata_resp.status < 500:
                self._delete_record()
                self._delete_tmp_file()
            self.obsClient.log_client.log(
                ERROR,
                'there are something wrong when touch the object {0}. ErrorCode:{1}, ErrorMessage:{2}'.format(
                    self.objectKey, metadata_resp.errorCode, metadata_resp.errorMessage))
            raise Exception(
                'there are something wrong when touch the object {0}. ErrorCode:{1}, ErrorMessage:{2}'.format(
                    self.objectKey, metadata_resp.status, metadata_resp.errorMessage))
        self._metadata_resp = metadata_resp

    def _delete_tmp_file(self):
        if os.path.exists(self._tmp_file):
            os.remove(self._tmp_file)

    def _do_rename(self):
        try:
            with open(self.fileName, 'wb') as wf:
                with open(self._tmp_file, 'rb') as rf:
                    while True:
                        chunk = rf.read(const.READ_ONCE_LENGTH)
                        if not chunk:
                            break
                        wf.write(chunk)
            if self.enableCheckPoint:
                self._delete_record()
            self._delete_tmp_file()
            return 1
        except Exception:
            return 0

    def _download(self):
        inner_notifier = False

        if self.enableCheckPoint:
            self._load()

        if "downloadParts" not in self._record:
            self._prepare()

        sent_bytes, unfinished_down_parts = self._download_prepare()

        try:
            if len(unfinished_down_parts) > 0:
                if (self.size - sent_bytes) > 0:
                    if self.progressCallback is not None:
                        self.notifier = progress.ProgressNotifier(self.progressCallback, self.size)
                        inner_notifier = True
                        self.notifier.start()
                    self.notifier.send(sent_bytes)

                thread_pools = _ThreadPool(functools.partial(self._produce, download_parts=unfinished_down_parts),
                                           [self._consume] * self.taskNum)
                thread_pools.run()

                if self._abort:
                    self._delete_record()
                    self._delete_tmp_file()
                    if self._exception is not None:
                        raise Exception(self._exception)

                for p in self._record['downloadParts']:
                    if not p['isCompleted']:
                        raise Exception('some parts are failed when download. Please try again')

            try:
                os.rename(self._tmp_file, self.fileName)
                if self.enableCheckPoint:
                    self._delete_record()
                self.obsClient.log_client.log(INFO, 'download success.')
                return self._metadata_resp
            except Exception as e:
                if self._do_rename():
                    self.obsClient.log_client.log(INFO, 'download success.')
                    return self._metadata_resp
                if not self.enableCheckPoint:
                    self._delete_tmp_file()
                self.obsClient.log_client.log(
                    INFO,
                    'Rename failed. The reason maybe:[the {0} exists, not a file path, not permission]. Please check.')
                raise e
        finally:
            if inner_notifier:
                self.notifier.end()

    def _download_prepare(self):
        sent_bytes = 0
        unfinished_down_parts = []
        for part in self._record['downloadParts']:
            if not part['isCompleted']:
                unfinished_down_parts.append(part)
            else:
                sent_bytes += (part['length'] - part['offset']) + 1
        return sent_bytes, unfinished_down_parts

    def _load(self):
        self._record = self._get_record()
        if self._record is not None and not (
                self._type_record(self._record) and self._check_download_record(self._record)):
            self._delete_record()
            self._delete_tmp_file()
            self._record = None
        if self._record is None:
            self._record = {'bucketName': self.bucketName, 'objectKey': self.objectKey, 'versionId': self.versionId,
                            'downloadFile': self.fileName, 'imageProcess': self.imageProcess}

    def _prepare(self):
        object_status = [self.objectKey, self.size, self.lastModified, self.versionId, self.imageProcess]
        with open(_to_unicode(self._tmp_file), 'wb') as f:
            if self.size > 0:
                f.seek(self.size - 1, 0)
            f.write('b' if const.IS_PYTHON2 else 'b'.encode('UTF-8'))

        tmp_file_status = [os.path.getsize(self._tmp_file), os.path.getmtime(self._tmp_file)]
        self._record["downloadParts"] = self._split_object()
        self._record["objectStatus"] = object_status
        self._record["tmpFileStatus"] = tmp_file_status
        self.obsClient.log_client.log(INFO, 'prepare new download task success.')
        if self.enableCheckPoint:
            self._write_record(self._record)

    def _type_record(self, record):
        try:
            for key in ('bucketName', 'objectKey', 'versionId', 'downloadFile', 'imageProcess'):
                if key == 'versionId' and record['versionId'] is None:
                    continue
                if key == 'imageProcess' and record['imageProcess'] is None:
                    continue
                if not isinstance(record[key], str):
                    self.obsClient.log_client.log(
                        ERROR,
                        '{0} is not a string type. {1} belong to {2}'.format(key, record[key], record[key].__class__)
                    )
                    return False
            if not isinstance(record['downloadParts'], list):
                self.obsClient.log_client.log(ERROR, 'downloadParts is not a list.It is {0} type'.format(
                    record['downloadParts'].__class__))
                return False
            if not isinstance(record['objectStatus'], list):
                self.obsClient.log_client.log(ERROR, 'objectStatus is not a list.It is {0} type'.format(
                    record['objectStatus'].__class__))
                return False
            if not isinstance(record['tmpFileStatus'], list):
                self.obsClient.log_client.log(ERROR, 'tmpFileStatus is not a dict.It is {0} type'.format(
                    record['tmpFileStatus'].__class__))
                return False
        except KeyError as e:
            self.obsClient.log_client.log(INFO, 'Key is not found:{0}'.format(e.args))
            return False
        return True

    def _check_download_record(self, record):
        if not operator.eq([record['bucketName'], record['objectKey'], record['versionId'], record['downloadFile'],
                            record['imageProcess']],
                           [self.bucketName, self.objectKey, self.versionId, self.fileName, self.imageProcess]):
            return False
        if not operator.eq(record['objectStatus'],
                           [self.objectKey, self.size, self.lastModified, self.versionId, self.imageProcess]):
            return False
        if record['tmpFileStatus'][0] != self.size:
            return False
        return True

    def _split_object(self):
        downloadParts = []
        num_counts = int(self.size / self.partSize)
        if num_counts >= 10000:
            self.partSize = int(self.size / 10000) if self.size % 10000 == 0 else int(self.size / 10000) + 1
            num_counts = int(self.size / self.partSize)
        if self.size % self.partSize != 0:
            num_counts += 1
        start = 0
        for i in range(1, num_counts + 1):
            end = start + util.to_long(self.partSize) if i != num_counts else util.to_long(self.size)
            part = Part(util.to_long(i), util.to_long(start), end - 1, False)
            start += self.partSize
            downloadParts.append(part)
        return downloadParts

    @staticmethod
    def _produce(ThreadPool, download_parts):
        for part in download_parts:
            ThreadPool.put(part)

    def _consume(self, ThreadPool):
        while ThreadPool.ok():
            part = ThreadPool.get()
            if part is None:
                break
            self._download_part(part)

    @staticmethod
    def _copy_get_object_header(src_header):
        get_object_header = GetObjectHeader()
        get_object_header.sseHeader = src_header.sseHeader
        get_object_header.if_match = src_header.if_match
        get_object_header.if_none_match = src_header.if_none_match
        get_object_header.if_modified_since = src_header.if_modified_since
        get_object_header.if_unmodified_since = src_header.if_unmodified_since
        return get_object_header

    def _download_part(self, part):
        get_object_request = GetObjectRequest(versionId=self.versionId, imageProcess=self.imageProcess)
        get_object_header = self._copy_get_object_header(self.header)
        get_object_header.range = util.to_string(part['offset']) + '-' + util.to_string(part['length'])
        if not self._is_abort():
            # todo 检视 response 的作用与 part_response 的重构
            response = None
            try:
                resp = self.obsClient.getObject(bucketName=self.bucketName, objectKey=self.objectKey,
                                                getObjectRequest=get_object_request,
                                                headers=get_object_header, notifier=self.notifier,
                                                extensionHeaders=self.extensionHeaders)
                if resp.status < 300:
                    part_response = resp.body.response
                    self._download_part_write(part_response, part)
                    self._record['downloadParts'][part['partNumber'] - 1]['isCompleted'] = True
                    if self.enableCheckPoint:
                        with self._lock:
                            self._write_record(self._record)
                else:
                    if 300 < resp.status < 500:
                        self._do_abort('errorCode:{0}, errorMessage:{1}'.format(resp.errorCode, resp.errorMessage))
                    self._exception += (
                        'response from server is something wrong. ErrorCode:{0}, ErrorMessage:{1}\n'.format(
                            resp.errorCode, resp.errorMessage))
                    self.obsClient.log_client.log(
                        ERROR,
                        'response from server is something wrong. ErrorCode:{0}, ErrorMessage:{1}'.format(
                            resp.errorCode, resp.errorMessage))
            except Exception as e:
                self.obsClient.log_client.log(DEBUG, 'download part %s error, %s' % (part['partNumber'], e))
                self.obsClient.log_client.log(ERROR, traceback.format_exc())
            finally:
                if response is not None:
                    part_response.close()

    def _download_part_write(self, response, part):
        chunk_size = const.READ_ONCE_LENGTH
        if response is not None:
            with open(_to_unicode(self._tmp_file), 'rb+') as fs:
                fs.seek(part['offset'], 0)
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    fs.write(chunk)


class Part(BaseModel):
    allowedAttr = {'partNumber': const.LONG, 'offset': const.LONG, 'length': const.LONG, 'isCompleted': bool}

    def __init__(self, partNumber, offset, length, isCompleted=False):
        self.partNumber = partNumber
        self.offset = offset
        self.length = length
        self.isCompleted = isCompleted


def _parse_string(content):
    if const.IS_PYTHON2:
        if isinstance(content, dict):
            return dict([(_parse_string(key), _parse_string(value)) for key, value in content.items()])
        elif isinstance(content, list):
            return [_parse_string(element) for element in content]
        elif isinstance(content, const.UNICODE):
            return content.encode('UTF-8')
    return content


def _to_unicode(data):
    if isinstance(data, bytes):
        return data.decode('UTF-8')
    return data


class _ThreadPool(object):
    def __init__(self, producer, consumers):
        self._producer = producer
        self._consumers = consumers
        self._lock = threading.Lock()
        self._queue = queue.Queue()

        self._threads_consumer = []
        self._threads_producer = []
        self._threading_thread = threading.Thread
        self._exc_info = None
        self._exc_stack = None

    def run(self):
        self._add_and_run(self._threading_thread(target=self._producer_start), self._threads_producer)
        for thread in self._threads_producer:
            thread.join()
        for consumer in self._consumers:
            self._add_and_run(self._threading_thread(target=self._consumer_start, args=(consumer,)),
                              self._threads_consumer)

        for thread in self._threads_consumer:
            thread.join()

        if self._exc_info:
            raise self._exc_info[1]

    def put(self, task):
        if task is not None:
            self._queue.put(task)

    def get(self):
        return self._queue.get()

    def ok(self):
        with self._lock:
            return self._exc_info is None

    @staticmethod
    def _add_and_run(thread, pool):
        thread.daemon = True
        thread.start()
        pool.append(thread)

    def _producer_start(self):
        try:
            self._producer(self)
        except Exception:
            with self._lock:
                if self._exc_info is None:
                    self._exc_info = sys.exc_info()
                    self._exc_stack = traceback.format_exc()
        finally:
            self._put_end()

    def _consumer_start(self, consumer):
        try:
            consumer(self)
        except Exception:
            with self._lock:
                if self._exc_info is None:
                    self._exc_info = sys.exc_info()
                    self._exc_stack = traceback.format_exc()

    def _put_end(self):
        length = len(self._consumers)
        for _ in range(length):
            self._queue.put(None)
