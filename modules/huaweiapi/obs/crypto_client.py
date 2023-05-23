# coding:utf-8

import io

from modules.huaweiapi.obs import GetObjectHeader, ObsClient, PutObjectHeader, UploadFileHeader, const, progress, util
from modules.huaweiapi.obs.ilog import INFO
from modules.huaweiapi.obs.transfer import _resume_download_with_operation, downloadOperation, uploadOperation


class CryptoObsClient(ObsClient):
    def __init__(self, cipher_generator, *args, **kwargs):
        self.cipher_generator = cipher_generator
        super(CryptoObsClient, self).__init__(*args, **kwargs)

    def appendObject(self, bucketName, objectKey, content=None, metadata=None, headers=None, progressCallback=None,
                     autoClose=True, extensionHeaders=None):
        raise Exception("AppendObject is not supported in CryptoObsClient")

    def copyPart(self, bucketName, objectKey, partNumber, uploadId, copySource, copySourceRange=None,
                 destSseHeader=None, sourceSseHeader=None, extensionHeaders=None):
        raise Exception("CopyPart is not supported in CryptoObsClient")

    def initiateMultipartUpload(self, bucketName, objectKey, acl=None, storageClass=None,
                                metadata=None, websiteRedirectLocation=None, contentType=None, sseHeader=None,
                                expires=None, extensionGrants=None, extensionHeaders=None, encoding_type=None):
        raise Exception("InitiateMultipartUpload is not supported in CryptoObsClient")

    def uploadPart(self, bucketName, objectKey, partNumber, uploadId, object=None, isFile=False, partSize=None,
                   offset=0, sseHeader=None, isAttachMd5=False, md5=None, content=None, progressCallback=None,
                   autoClose=True, extensionHeaders=None):
        raise Exception("UploadPart is not supported in CryptoObsClient")

    def initiateEncryptedMultipartUpload(self, bucketName, objectKey, crypto_cipher, acl=None, storageClass=None,
                                         metadata=None, websiteRedirectLocation=None, contentType=None, sseHeader=None,
                                         expires=None, extensionGrants=None, extensionHeaders=None, encoding_type=None):
        if self.cipher_generator.need_sha256:
            raise Exception("Could not calculate sha256 for initiateMultipartUpload")
        if metadata is None:
            metadata = dict()
        content = crypto_cipher
        metadata = content.gen_need_metadata_and_headers(metadata, UploadFileHeader())
        resp = super(CryptoObsClient, self).initiateMultipartUpload(bucketName, objectKey, acl, storageClass, metadata,
                                                                    websiteRedirectLocation, contentType, sseHeader,
                                                                    expires, extensionGrants,
                                                                    extensionHeaders, encoding_type)
        resp.body["crypto_info"] = content.safe_crypto_info()
        content.close()
        return resp

    def putContent(self, bucketName, objectKey, content=None, metadata=None, headers=None,
                   progressCallback=None, autoClose=True, extensionHeaders=None):
        if headers is None:
            headers = PutObjectHeader()
        if (const.IS_PYTHON2 and isinstance(content, unicode)) or isinstance(content, str):
            content = self._covert_string_to_bytes_io(content)
            headers.contentLength = content.seek(0, 2)
            content.seek(0)
        elif self.cipher_generator.need_sha256:
            # 如果不是字符串，不允许计算 sha256
            raise Exception("Could not calculate sha256 for a stream object")
        content = self.cipher_generator.new(content)
        if metadata is None:
            metadata = dict()
        metadata = content.gen_need_metadata_and_headers(metadata, headers)
        put_result = super(CryptoObsClient, self).putContent(bucketName, objectKey, content, metadata, headers=headers,
                                                             progressCallback=progressCallback, autoClose=autoClose,
                                                             extensionHeaders=extensionHeaders)
        return put_result

    def _gen_readable_object_from_file(self, file_path):
        return self.cipher_generator.new(open(file_path, "rb"))

    def putObject(self, bucketName, objectKey, content, metadata=None, headers=None, progressCallback=None,
                  autoClose=True, extensionHeaders=None):
        raise Exception("putObject is not supported in CryptoObsClient")

    def uploadEncryptedPart(self, bucketName, objectKey, partNumber, uploadId, crypto_cipher, object=None,
                            isFile=False, partSize=None, offset=0, sseHeader=None, isAttachMd5=False, md5=None,
                            content=None, progressCallback=None, autoClose=True, extensionHeaders=None):
        if isAttachMd5:
            raise Exception("Could not calculate md5 for uploadEncryptedPart")
        if content is None:
            content = object
        if isFile:
            checked_file_part_info = self._check_file_part_info(content, offset, partSize)
            content = crypto_cipher
            content._file = open(checked_file_part_info["file_path"], "rb")
            content._file.seek(checked_file_part_info["offset"])
            partSize = checked_file_part_info["partSize"]
        else:
            if content is not None and hasattr(content, 'read') and callable(content.read):
                crypto_cipher._file = content
            else:
                crypto_cipher._file = self._covert_string_to_bytes_io(content)
            content = crypto_cipher
        return super(CryptoObsClient, self).uploadPart(bucketName, objectKey, partNumber, uploadId,
                                                       object=None, isFile=False, partSize=partSize,
                                                       offset=0, sseHeader=sseHeader,
                                                       isAttachMd5=isAttachMd5, md5=md5, content=content,
                                                       progressCallback=progressCallback,
                                                       autoClose=autoClose, extensionHeaders=extensionHeaders)

    def uploadFile(self, bucketName, objectKey, uploadFile, partSize=9 * 1024 * 1024,
                   taskNum=1, enableCheckpoint=False, checkpointFile=None,
                   checkSum=False, metadata=None, progressCallback=None, headers=None,
                   extensionHeaders=None, encoding_type=None):
        self.log_client.log(INFO, 'enter resume upload file...')
        self._assert_not_null(bucketName, 'bucketName is empty')
        self._assert_not_null(objectKey, 'objectKey is empty')
        self._assert_not_null(uploadFile, 'uploadFile is empty')
        upload_operation = EncryptedUploadOperation(self.cipher_generator, util.to_string(bucketName),
                                                    util.to_string(objectKey),
                                                    util.to_string(uploadFile), partSize, taskNum, enableCheckpoint,
                                                    util.to_string(checkpointFile), checkSum, metadata,
                                                    progressCallback, self, headers, extensionHeaders=extensionHeaders,
                                                    encoding_type=encoding_type)
        return upload_operation._upload()

    def downloadFile(self, bucketName, objectKey, downloadFile=None, partSize=5 * 1024 * 1024, taskNum=1,
                     enableCheckpoint=False, checkpointFile=None, header=None, versionId=None,
                     progressCallback=None, imageProcess=None, extensionHeaders=None):
        if header is None:
            header = GetObjectHeader()
        if downloadFile is None:
            downloadFile = objectKey

        down_operation = DecryptedDownloadOperation(self.cipher_generator, util.to_string(bucketName),
                                                    util.to_string(objectKey), util.to_string(downloadFile),
                                                    partSize, taskNum, enableCheckpoint, util.to_string(checkpointFile),
                                                    header, versionId, progressCallback, self, imageProcess,
                                                    progress.NONE_NOTIFIER, extensionHeaders=extensionHeaders)
        return _resume_download_with_operation(down_operation)

    def _parse_content(self, objectKey, conn, readable, result_wrapper=None, download_start=None,
                       downloadPath=None, chuckSize=const.READ_ONCE_LENGTH, loadStreamInMemory=False,
                       progressCallback=None, notifier=None):
        if readable.status >= 300:
            return super(CryptoObsClient, self)._parse_content(objectKey, conn, readable,
                                                               download_start=download_start, downloadPath=downloadPath,
                                                               chuckSize=chuckSize,
                                                               loadStreamInMemory=loadStreamInMemory,
                                                               progressCallback=progressCallback, notifier=notifier)
        crypto_info = self.cipher_generator.get_crypto_info_from_headers(dict(readable.getheaders()))
        try:
            iv_offset = int(download_start.split("-")[0])
        except (AttributeError, ValueError):
            iv_offset = 0
        decryptedObject = self.cipher_generator.new(readable, is_decrypt=True, crypto_info=crypto_info)
        decryptedObject.seek_iv(iv_offset)
        return super(CryptoObsClient, self)._parse_content(objectKey, conn, decryptedObject,
                                                           download_start=download_start, downloadPath=downloadPath,
                                                           chuckSize=chuckSize, loadStreamInMemory=loadStreamInMemory,
                                                           progressCallback=progressCallback, notifier=notifier)

    def _encrypted_upload_part(self, bucketName, objectKey, partNumber, uploadId, crypto_info,
                               content=None, partSize=None, offset=0, sseHeader=None, isAttachMd5=False,
                               md5=None, notifier=None, extensionHeaders=None):
        checked_file_part_info = self._check_file_part_info(content, offset, partSize)
        content = self.cipher_generator.new(open(checked_file_part_info["file_path"], "rb"), crypto_info=crypto_info)
        content.seek(checked_file_part_info["offset"])
        headers = dict()
        if self.cipher_generator.need_sha256:
            headers[self.ha.content_sha256_header()] = content.calculate_sha256(partSize)[1]
        return super(CryptoObsClient, self)._uploadPartWithNotifier(bucketName, objectKey, partNumber, uploadId,
                                                                    content, False, checked_file_part_info["partSize"],
                                                                    checked_file_part_info["offset"], sseHeader,
                                                                    isAttachMd5, md5, notifier, extensionHeaders,
                                                                    headers)

    def gen_readable_object_from_file(self, file_path):
        content = self.cipher_generator.new(open(file_path, "rb"))
        return content

    @staticmethod
    def add_metadata_from_content(metadata, headers, content):
        return content.gen_need_metadata_and_headers(metadata, headers)

    @staticmethod
    def _covert_string_to_bytes_io(str_object):
        if const.IS_PYTHON2 and isinstance(str_object, unicode) \
                or (not const.IS_PYTHON2 and isinstance(str_object, str)):
            return io.BytesIO(str_object.encode("UTF-8"))
        return io.BytesIO(str_object)


class EncryptedUploadOperation(uploadOperation):
    def __init__(self, cipher_generator, bucketName, objectKey, uploadFile, partSize, taskNum, enableCheckPoint,
                 checkPointFile, checkSum, metadata, progressCallback, obsClient, headers, extensionHeaders=None,
                 encoding_type=None):
        self.cipher_generator = cipher_generator
        self.encrypted_content = cipher_generator.new(open(uploadFile, "rb"))
        self.crypto_info = self.encrypted_content.safe_crypto_info()
        if metadata is None:
            metadata = dict()
        if headers is None:
            headers = UploadFileHeader()
        metadata = self.encrypted_content.gen_need_metadata_and_headers(metadata, headers)
        super(EncryptedUploadOperation, self).__init__(bucketName, objectKey, uploadFile, partSize, taskNum,
                                                       enableCheckPoint, checkPointFile, checkSum, metadata,
                                                       progressCallback, obsClient, headers, extensionHeaders,
                                                       encoding_type)
        self._record = self.encrypted_content.gen_need_record(self._record)

    def _check_upload_record(self, record):
        self._record = self._get_record()
        if not self.cipher_generator.check_upload_record(self._record, self.encrypted_content.safe_crypto_info()):
            self.obsClient.log_client.log(INFO, 'The crypto_info was changed. clear the record')
            return False
        return super(EncryptedUploadOperation, self)._check_upload_record(record)

    def _load(self):
        super(EncryptedUploadOperation, self)._load()
        # 如果 record 通过校验，使用 record 里的信息初始化新 cipher, 否则使用当前的 cipher 补全 record 信息
        if "crypto_mod" in self._record:
            self.encrypted_content = self.cipher_generator.new("", crypto_info=self._record)
        else:
            self._record = self.encrypted_content.gen_need_record(self._record)

    def _upload(self):
        try:
            return super(EncryptedUploadOperation, self)._upload()
        finally:
            self.encrypted_content.close()

    def get_upload_part_resp(self, part):
        return self.obsClient._encrypted_upload_part(self.bucketName, self.objectKey, part['partNumber'],
                                                     self._record['uploadId'],
                                                     self.encrypted_content.crypto_info(),
                                                     self.fileName, partSize=part['length'],
                                                     offset=part['offset'], notifier=self.notifier,
                                                     extensionHeaders=self.extensionHeaders,
                                                     sseHeader=self.headers.sseHeader)

    def get_init_upload_result(self):
        return super(self.obsClient.__class__, self.obsClient).initiateMultipartUpload(
            self.bucketName, self.objectKey, metadata=self.metadata, acl=self.headers.acl,
            storageClass=self.headers.storageClass, websiteRedirectLocation=self.headers.websiteRedirectLocation,
            contentType=self.headers.contentType, sseHeader=self.headers.sseHeader,
            expires=self.headers.expires, extensionGrants=self.headers.extensionGrants,
            extensionHeaders=self.extensionHeaders, encoding_type=self.encoding_type)


class DecryptedDownloadOperation(downloadOperation):
    def __init__(self, cipher_generator, *args, **kwargs):
        super(DecryptedDownloadOperation, self).__init__(*args, **kwargs)
        self.cipher_generator = cipher_generator
        header_dict = dict(self._metadata_resp.header)
        crypto_info = self.cipher_generator.get_crypto_info_from_headers(header_dict)
        # 用空字符串生成个临时加密下载对象，用以获取加密信息
        self.decrypted_content = cipher_generator.new("", crypto_info=crypto_info)

    def _check_download_record(self, record):
        self._record = self._get_record()
        if not self.cipher_generator.check_download_record(self._record, self.decrypted_content.safe_crypto_info()):
            self.obsClient.log_client.log(INFO, 'The crypto_info was changed. clear the record')
            return False
        return super(DecryptedDownloadOperation, self)._check_download_record(record)

    def _load(self):
        super(DecryptedDownloadOperation, self)._load()
        self._record = self.decrypted_content.gen_need_record(self._record)

    def _download(self):
        try:
            return super(DecryptedDownloadOperation, self)._download()
        finally:
            self.decrypted_content.close()
