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

try:
    import xml.etree.cElementTree as ET
except Exception:
    import xml.etree.ElementTree as ET

import json
from modules.huaweiapi.obs import util
from modules.huaweiapi.obs import const
from modules.huaweiapi.obs.model import SseCHeader, SseKmsHeader, Owner, Bucket, ListBucketsResponse, GetBucketMetadataResponse, \
    LocationResponse, GetBucketStorageInfoResponse, Policy, GetBucketStoragePolicyResponse, GetBucketQuotaResponse, \
    GetBucketEncryptionResponse, TagInfo, CommonPrefix, ObjectVersions, OptionsResponse, ErrorResult, \
    DeleteObjectsResponse, DeleteObjectResponse, Expiration, LifecycleResponse, Lifecycle, RedirectAllRequestTo, \
    WebsiteConfiguration, IndexDocument, ErrorDocument, RoutingRule, Notification, TopicConfiguration, Initiator, \
    ListMultipartUploadsResponse, Part, ACL, Logging, PutContentResponse, AppendObjectResponse, \
    InitiateMultipartUploadResponse, CopyObjectResponse, GetObjectMetadataResponse, SetObjectMetadataResponse, \
    UploadPartResponse, CopyPartResponse, Replication, GetBucketRequestPaymentResponse
from modules.huaweiapi.obs.model import FetchPolicy, SetBucketFetchJobResponse, GetBucketFetchJobResponse, FetchJobResponse, \
    ListWorkflowTemplateResponse
from modules.huaweiapi.obs.model import GetWorkflowResponse, UpdateWorkflowResponse, ListWorkflowResponse, \
    AsyncAPIStartWorkflowResponse, ListWorkflowExecutionResponse, GetWorkflowExecutionResponse, \
    RestoreFailedWorkflowExecutionResponse, GetTriggerPolicyResponse, CreateWorkflowTemplateResponse, \
    GetWorkflowTemplateResponse, CreateWorkflowResponse
from modules.huaweiapi.obs.model import DateTime, ListObjectsResponse, Content, CorsRule, ObjectVersionHead, ObjectVersion, \
    ObjectDeleteMarker, DeleteObjectResult, NoncurrentVersionExpiration, NoncurrentVersionTransition, Rule, Condition, \
    Redirect, FilterRule, FunctionGraphConfiguration, Upload, CompleteMultipartUploadResponse, ListPartsResponse, \
    Grant, ReplicationRule, Transition, Grantee, BucketAliasModel, ListBucketAliasModel

if const.IS_PYTHON2:
    from urllib import unquote_plus, quote_plus
else:
    from urllib.parse import unquote_plus, quote_plus


class Adapter(object):
    OBS_ALLOWED_ACL_CONTROL = ['private', 'public-read', 'public-read-write', 'public-read-delivered',
                               'public-read-write-delivered', 'bucket-owner-full-control']
    V2_ALLOWED_ACL_CONTROL = ['private', 'public-read', 'public-read-write', 'authenticated-read', 'bucket-owner-read',
                              'bucket-owner-full-control', 'log-delivery-write']

    OBS_ALLOWED_STORAGE_CLASS = ['STANDARD', 'WARM', 'COLD']
    V2_ALLOWED_STORAGE_CLASS = ['STANDARD', 'STANDARD_IA', 'GLACIER']

    OBS_ALLOWED_GROUP = ['Everyone']
    V2_ALLOWED_GROUP = ['http://acs.amazonaws.com/groups/global/AllUsers',
                        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
                        'http://acs.amazonaws.com/groups/s3/LogDelivery']

    OBS_ALLOWED_RESTORE_TIER = ['Expedited', 'Standard']
    V2_ALLOWED_RESTORE_TIER = ['Expedited', 'Standard', 'Bulk']

    OBS_ALLOWED_EVENT_TYPE = ['ObjectCreated:*', 'ObjectCreated:Put', 'ObjectCreated:Post', 'ObjectCreated:Copy',
                              'ObjectCreated:CompleteMultipartUpload', 'ObjectRemoved:*', 'ObjectRemoved:Delete',
                              'ObjectRemoved:DeleteMarkerCreated']
    V2_ALLOWED_EVENT_TYPE = ['s3:ObjectCreated:*', 's3:ObjectCreated:Put', 's3:ObjectCreated:Post',
                             's3:ObjectCreated:Copy',
                             's3:ObjectCreated:CompleteMultipartUpload', 's3:ObjectRemoved:*',
                             's3:ObjectRemoved:Delete', 's3:ObjectRemoved:DeleteMarkerCreated']

    def __init__(self, signature):
        self.is_obs = signature.lower() == 'obs'

    def _get_header_prefix(self):
        return const.OBS_HEADER_PREFIX if self.is_obs else const.V2_HEADER_PREFIX

    def _get_meta_header_prefix(self):
        return const.OBS_META_HEADER_PREFIX if self.is_obs else const.V2_META_HEADER_PREFIX

    def auth_prefix(self):
        return 'OBS' if self.is_obs else 'AWS'

    def acl_header(self):
        return self._get_header_prefix() + 'acl'

    def epid_header(self):
        return self._get_header_prefix() + 'epid'

    @staticmethod
    def pfs_header():
        return 'x-obs-fs-file-interface'

    def date_header(self):
        return self._get_header_prefix() + 'date'

    def security_token_header(self):
        return self._get_header_prefix() + 'security-token'

    def content_sha256_header(self):
        return self._get_header_prefix() + 'content-sha256'

    def default_storage_class_header(self):
        return self._get_header_prefix() + 'storage-class' if self.is_obs else 'x-default-storage-class'

    @staticmethod
    def az_redundancy_header():
        return 'x-obs-az-redundancy'

    def storage_class_header(self):
        return self._get_header_prefix() + 'storage-class'

    def request_id_header(self):
        return self._get_header_prefix() + 'request-id'

    @staticmethod
    def indicator_header():
        return 'x-reserved-indicator'

    def location_header(self):
        return self._get_header_prefix() + 'location'

    @staticmethod
    def queryPFS_header():
        return 'x-obs-bucket-type'

    def bucket_region_header(self):
        return self._get_header_prefix() + 'bucket-location' if self.is_obs \
            else self._get_header_prefix() + 'bucket-region'

    @staticmethod
    def server_version_header():
        return 'x-obs-version'

    def version_id_header(self):
        return self._get_header_prefix() + 'version-id'

    def copy_source_version_id(self):
        return self._get_header_prefix() + 'copy-source-version-id'

    def delete_marker_header(self):
        return self._get_header_prefix() + 'delete-marker'

    def sse_kms_header(self):
        return self._get_header_prefix() + 'server-side-encryption'

    def sse_kms_key_header(self):
        return self._get_header_prefix() + 'server-side-encryption-kms-key-id' if self.is_obs \
            else self._get_header_prefix() + 'server-side-encryption-aws-kms-key-id'

    def copy_source_sse_c_header(self):
        return self._get_header_prefix() + 'copy-source-server-side-encryption-customer-algorithm'

    def copy_source_sse_c_key_header(self):
        return self._get_header_prefix() + 'copy-source-server-side-encryption-customer-key'

    def copy_source_sse_c_key_md5_header(self):
        return self._get_header_prefix() + 'copy-source-server-side-encryption-customer-key-MD5'

    def sse_c_header(self):
        return self._get_header_prefix() + 'server-side-encryption-customer-algorithm'

    def sse_c_key_header(self):
        return self._get_header_prefix() + 'server-side-encryption-customer-key'

    def sse_c_key_md5_header(self):
        return self._get_header_prefix() + 'server-side-encryption-customer-key-MD5'

    def website_redirect_location_header(self):
        return self._get_header_prefix() + 'website-redirect-location'

    @staticmethod
    def success_action_redirect_header():
        return 'success-action-redirect'

    def restore_header(self):
        return self._get_header_prefix() + 'restore'

    @staticmethod
    def expires_header():
        return 'x-obs-expires'

    def expiration_header(self):
        return self._get_header_prefix() + 'expiration'

    def copy_source_header(self):
        return self._get_header_prefix() + 'copy-source'

    def copy_source_range_header(self):
        return self._get_header_prefix() + 'copy-source-range'

    def metadata_directive_header(self):
        return self._get_header_prefix() + 'metadata-directive'

    def copy_source_if_match_header(self):
        return self._get_header_prefix() + 'copy-source-if-match'

    def copy_source_if_none_match_header(self):
        return self._get_header_prefix() + 'copy-source-if-none-match'

    def copy_source_if_modified_since_header(self):
        return self._get_header_prefix() + 'copy-source-if-modified-since'

    def copy_source_if_unmodified_since_header(self):
        return self._get_header_prefix() + 'copy-source-if-unmodified-since'

    @staticmethod
    def next_position_header():
        return 'x-obs-next-append-position'

    @staticmethod
    def object_type_header():
        return 'x-obs-object-type'

    def request_payer_header(self):
        return self._get_header_prefix() + 'request-payer'

    def location_clustergroup_id_header(self):
        return self._get_header_prefix() + const.LOCATION_CLUSTERGROUP_ID

    def oef_marker_header(self):
        return self._get_header_prefix() + 'oef-marker'

    def adapt_group(self, group):
        if self.is_obs:
            return self._adapt_group_is_obs(group)
        return group if group in self.V2_ALLOWED_GROUP else 'http://acs.amazonaws.com/groups/global/AllUsers' \
            if group == 'Everyone' else 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' if \
            group == 'AuthenticatedUsers' else 'http://acs.amazonaws.com/groups/s3/LogDelivery' \
            if group == 'LogDelivery' else None

    def _adapt_group_is_obs(self, group):
        return group if group in self.OBS_ALLOWED_GROUP else 'Everyone' \
            if group in ('http://acs.amazonaws.com/groups/global/AllUsers', 'AllUsers') else None

    def adapt_restore_tier(self, tier):
        if self.is_obs:
            return tier if tier in self.OBS_ALLOWED_RESTORE_TIER else None

        return tier if tier in self.V2_ALLOWED_RESTORE_TIER else None

    def adapt_acl_control(self, aclControl):
        if self.is_obs:
            return aclControl if aclControl in self.OBS_ALLOWED_ACL_CONTROL else None

        return aclControl if aclControl in self.V2_ALLOWED_ACL_CONTROL else None

    def adapt_event_type(self, eventType):
        if self.is_obs:
            return eventType if eventType in self.OBS_ALLOWED_EVENT_TYPE \
                else eventType[3:] if eventType in self.V2_ALLOWED_EVENT_TYPE else None

        return eventType if eventType in self.V2_ALLOWED_EVENT_TYPE \
            else 's3:' + eventType if eventType in self.OBS_ALLOWED_EVENT_TYPE else None

    def adapt_storage_class(self, storageClass):
        if self.is_obs:
            return storageClass if storageClass in self.OBS_ALLOWED_STORAGE_CLASS \
                else 'WARM' if storageClass == 'STANDARD_IA' else 'COLD' if storageClass == 'GLACIER' else None
        return storageClass if storageClass in self.V2_ALLOWED_STORAGE_CLASS \
            else 'STANDARD_IA' if storageClass == 'WARM' else 'GLACIER' if storageClass == 'COLD' else None

    def adapt_extension_permission(self, permission, is_bucket=True):
        header = None
        if permission is not None and permission.startswith(self._get_header_prefix()):
            permission = permission[len(self._get_header_prefix()):]
        if permission == 'READ':
            header = 'grant-read'
        elif permission == 'WRITE':
            if is_bucket:
                header = 'grant-write'
        elif permission == 'READ_ACP':
            header = 'grant-read-acp'
        elif permission == 'WRITE_ACP':
            header = 'grant-write-acp'
        elif permission == 'FULL_CONTROL':
            header = 'grant-full-control'
        elif permission == 'READ_DELIVERED':
            if is_bucket:
                header = 'grant-read-delivered'
        elif permission == 'FULL_CONTROL_DELIVERED':
            if is_bucket:
                header = 'grant-full-control-delivered'
        return self._get_header_prefix() + header if header is not None else None


class Convertor(object):
    def __init__(self, signature, ha=None):
        self.is_obs = signature.lower() == 'obs'
        self.ha = ha

    @staticmethod
    def url_encode(value, encoding_type):
        if encoding_type and encoding_type.lower() == "url":
            if const.IS_PYTHON2 and isinstance(value, unicode):
                value = quote_plus(util.safe_encode(value))
                return value
            value = quote_plus(value)
        return value

    @staticmethod
    def _put_key_value(headers, key, value):
        if value is not None:
            if const.IS_PYTHON2:
                value = util.safe_encode(value)
            value = util.to_string(value)
            if util.is_valid(value):
                headers[key] = value

    def trans_create_bucket(self, **kwargs):
        headers = {}
        header = kwargs.get('header')
        if header is not None:
            self._put_key_value(headers, self.ha.acl_header(), self.ha.adapt_acl_control(header.get('aclControl')))
            self._put_key_value(headers, self.ha.default_storage_class_header(),
                                self.ha.adapt_storage_class(header.get('storageClass')))
            self._put_key_value(headers, self.ha.az_redundancy_header(), header.get('availableZone'))
            self._put_key_value(headers, self.ha.epid_header(), header.get('epid'))
            if header.get('isPFS'):
                self._put_key_value(headers, self.ha.pfs_header(), "Enabled")
            extensionGrants = header.get('extensionGrants')
            if extensionGrants is not None and len(extensionGrants) > 0:
                grantDict = {}
                for extensionGrant in extensionGrants:
                    permission = self.ha.adapt_extension_permission(extensionGrant.get('permission'))
                    if permission is not None and extensionGrant.get('granteeId') is not None:
                        granteeIds = grantDict.get(permission)
                        if granteeIds is None:
                            granteeIds = set()
                            grantDict[permission] = granteeIds
                        granteeIds.add('id=%s' % util.to_string(extensionGrant['granteeId']))

                for key, value in grantDict.items():
                    self._put_key_value(headers, key, ','.join(value))
        return {'headers': headers, 'entity': None if kwargs.get('location') is None else self.trans_bucket_location(
            kwargs.get('location'))}

    def trans_bucket_location(self, location):
        root = ET.Element('CreateBucketConfiguration')
        ET.SubElement(root, 'Location' if self.is_obs else 'LocationConstraint').text = util.to_string(location)
        return ET.tostring(root, 'UTF-8')

    def trans_list_buckets(self, **kwargs):
        headers = {}
        if kwargs.get('isQueryLocation'):
            self._put_key_value(headers, self.ha.location_header(), 'true')
        if kwargs.get('bucketType'):
            self._put_key_value(headers, self.ha.queryPFS_header(), kwargs.get('bucketType'))
        return {'headers': headers}

    def trans_list_objects(self, **kwargs):
        pathArgs = {}
        self._put_key_value(pathArgs, 'prefix', kwargs.get('prefix'))
        self._put_key_value(pathArgs, 'marker', kwargs.get('marker'))
        self._put_key_value(pathArgs, 'delimiter', kwargs.get('delimiter'))
        self._put_key_value(pathArgs, 'max-keys', kwargs.get('max_keys'))
        self._put_key_value(pathArgs, 'encoding-type', kwargs.get('encoding_type'))
        return {'pathArgs': pathArgs}

    def trans_list_versions(self, **kwargs):
        pathArgs = {'versions': None}
        version = kwargs.get('version')
        if version is not None:
            self._put_key_value(pathArgs, 'prefix', version.get('prefix'))
            self._put_key_value(pathArgs, 'key-marker', version.get('key_marker'))
            self._put_key_value(pathArgs, 'max-keys', version.get('max_keys'))
            self._put_key_value(pathArgs, 'delimiter', version.get('delimiter'))
            self._put_key_value(pathArgs, 'version-id-marker', version.get('version_id_marker'))
            self._put_key_value(pathArgs, 'encoding-type', version.get('encoding_type'))
        return {'pathArgs': pathArgs}

    def trans_get_bucket_metadata(self, **kwargs):
        headers = {}
        self._put_key_value(headers, const.ORIGIN_HEADER, kwargs.get('origin'))
        requestHeaders = kwargs.get('requestHeaders')
        _requestHeaders = requestHeaders[0] if isinstance(requestHeaders, list) and len(
            requestHeaders) == 1 else requestHeaders
        self._put_key_value(headers, const.ACCESS_CONTROL_REQUEST_HEADERS_HEADER, _requestHeaders)
        return {'headers': headers}

    def trans_get_bucket_storage_policy(self):
        return {
            'pathArgs': {'storageClass' if self.is_obs else 'storagePolicy': None},
        }

    def trans_set_bucket_storage_policy(self, **kwargs):
        return {
            'pathArgs': {'storageClass' if self.is_obs else 'storagePolicy': None},
            'entity': self.trans_storage_policy(kwargs.get('storageClass'))
        }

    def trans_storage_policy(self, storageClass):
        if self.is_obs:
            root = ET.Element('StorageClass')
            root.text = util.to_string(self.ha.adapt_storage_class(util.to_string(storageClass)))
            return ET.tostring(root, 'UTF-8')

        root = ET.Element('StoragePolicy')
        ET.SubElement(root, 'DefaultStorageClass').text = util.to_string(
            self.ha.adapt_storage_class(util.to_string(storageClass)))
        return ET.tostring(root, 'UTF-8')

    def trans_encryption(self, encryption, key=None):
        root = ET.Element('ServerSideEncryptionConfiguration')
        rule = ET.SubElement(root, 'Rule')
        sse = ET.SubElement(rule, 'ApplyServerSideEncryptionByDefault')
        if encryption == 'kms' and not self.is_obs:
            encryption = 'aws:kms'
        ET.SubElement(sse, 'SSEAlgorithm').text = util.to_string(encryption)
        if key is not None:
            ET.SubElement(sse, 'KMSMasterKeyID').text = util.to_string(key)
        return ET.tostring(root, 'UTF-8')

    @staticmethod
    def trans_quota(quota):
        root = ET.Element('Quota')
        ET.SubElement(root, 'StorageQuota').text = util.to_string(quota)
        return ET.tostring(root, 'UTF-8')

    def trans_set_bucket_tagging(self, **kwargs):
        entity = self.trans_tag_info(kwargs.get('tagInfo'))
        return {
            'pathArgs': {'tagging': None},
            'headers': {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))},
            'entity': entity
        }

    @staticmethod
    def trans_tag_info(tagInfo):
        root = ET.Element('Tagging')
        tagSetEle = ET.SubElement(root, 'TagSet')
        if tagInfo.get('tagSet') is not None and len(tagInfo['tagSet']) > 0:
            for tag in tagInfo['tagSet']:
                if tag.get('key') is not None and tag.get('value') is not None:
                    tagEle = ET.SubElement(tagSetEle, 'Tag')
                    ET.SubElement(tagEle, 'Key').text = util.safe_decode(tag['key'])
                    ET.SubElement(tagEle, 'Value').text = util.safe_decode(tag['value'])
        return ET.tostring(root, 'UTF-8')

    def trans_set_bucket_cors(self, **kwargs):
        entity = self.trans_cors_rules(kwargs.get('corsRuleList'))
        headers = {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))}
        return {'pathArgs': {'cors': None}, 'headers': headers, 'entity': entity}

    @staticmethod
    def trans_cors_rules(corsRuleList):
        root = ET.Element('CORSConfiguration')
        for cors in corsRuleList:
            corsRuleEle = ET.SubElement(root, 'CORSRule')
            if cors.get('id') is not None:
                ET.SubElement(corsRuleEle, 'ID').text = util.to_string(cors['id'])
            if cors.get('allowedMethod') is not None:
                for v in cors['allowedMethod']:
                    ET.SubElement(corsRuleEle, 'AllowedMethod').text = util.to_string(v)
            if cors.get('allowedOrigin') is not None:
                for v in cors['allowedOrigin']:
                    ET.SubElement(corsRuleEle, 'AllowedOrigin').text = util.to_string(v)
            if cors.get('allowedHeader') is not None:
                for v in cors['allowedHeader']:
                    ET.SubElement(corsRuleEle, 'AllowedHeader').text = util.to_string(v)
            if cors.get('maxAgeSecond') is not None:
                ET.SubElement(corsRuleEle, 'MaxAgeSeconds').text = util.to_string(cors['maxAgeSecond'])
            if cors.get('exposeHeader') is not None:
                for v in cors['exposeHeader']:
                    ET.SubElement(corsRuleEle, 'ExposeHeader').text = util.to_string(v)
        return ET.tostring(root, 'UTF-8')

    def trans_delete_objects(self, **kwargs):
        entity = self.trans_delete_objects_request(kwargs.get('deleteObjectsRequest'))
        headers = {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))}
        return {'pathArgs': {'delete': None}, 'headers': headers, 'entity': entity}

    def trans_delete_objects_request(self, deleteObjectsRequest):
        root = ET.Element('Delete')
        encoding_type = None
        if deleteObjectsRequest is not None:
            if deleteObjectsRequest.get('quiet') is not None:
                ET.SubElement(root, 'Quiet').text = util.to_string(deleteObjectsRequest['quiet']).lower()
            if deleteObjectsRequest.get('encoding_type') is not None:
                ET.SubElement(root, 'EncodingType').text = util.to_string(deleteObjectsRequest['encoding_type'])
                encoding_type = util.to_string(deleteObjectsRequest['encoding_type'])
            if isinstance(deleteObjectsRequest.get('objects'), list) and len(deleteObjectsRequest['objects']) > 0:
                for obj in deleteObjectsRequest['objects']:
                    if obj.get('key') is not None:
                        objectEle = ET.SubElement(root, 'Object')
                        key_text = self.url_encode(obj['key'], encoding_type)
                        ET.SubElement(objectEle, 'Key').text = util.safe_decode(key_text)
                        if obj.get('versionId') is not None:
                            ET.SubElement(objectEle, 'VersionId').text = util.safe_decode(obj['versionId'])
        return ET.tostring(root, 'UTF-8')

    @staticmethod
    def trans_version_status(status):
        root = ET.Element('VersioningConfiguration')
        ET.SubElement(root, 'Status').text = util.to_string(status)
        return ET.tostring(root, 'UTF-8')

    def trans_set_bucket_lifecycle(self, **kwargs):
        entity = self.trans_lifecycle(kwargs.get('lifecycle'))
        headers = {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))}
        return {'pathArgs': {'lifecycle': None}, 'headers': headers, 'entity': entity}

    def _transTransition(self, ruleEle, transition):
        transitionEle = ET.SubElement(ruleEle, 'Transition')
        if transition.get('days') is not None:
            ET.SubElement(transitionEle, 'Days').text = util.to_string(transition['days'])
        elif transition.get('date') is not None:
            date = transition['date'].ToUTMidTime() if isinstance(transition['date'], DateTime) else transition['date']
            ET.SubElement(transitionEle, 'Date').text = util.to_string(date)
        ET.SubElement(transitionEle, 'StorageClass').text = util.to_string(
            self.ha.adapt_storage_class(transition.get('storageClass')))

    def _transNoncurrentVersionTransition(self, ruleEle, noncurrentVersionTransition):
        noncurrentVersionTransitionEle = ET.SubElement(ruleEle, 'NoncurrentVersionTransition')
        if noncurrentVersionTransition.get('noncurrentDays') is not None:
            ET.SubElement(noncurrentVersionTransitionEle, 'NoncurrentDays').text = util.to_string(
                noncurrentVersionTransition['noncurrentDays'])
        ET.SubElement(noncurrentVersionTransitionEle, 'StorageClass').text = util.to_string(
            self.ha.adapt_storage_class(noncurrentVersionTransition['storageClass']))

    def trans_lifecycle(self, lifecycle):
        root = ET.Element('LifecycleConfiguration')
        rules = lifecycle.get('rule')
        if rules is not None and len(rules) > 0:
            for item in rules:
                ruleEle = ET.SubElement(root, 'Rule')
                if item.get('id') is not None:
                    ET.SubElement(ruleEle, 'ID').text = util.safe_decode(item['id'])
                if item.get('prefix') is not None:
                    ET.SubElement(ruleEle, 'Prefix').text = util.safe_decode(item['prefix'])
                ET.SubElement(ruleEle, 'Status').text = util.to_string(item.get('status'))

                ruleEle = self._trans_lifecycle_transition_expiration(item, ruleEle)

                if item.get('noncurrentVersionTransition') is not None:
                    if isinstance(item['noncurrentVersionTransition'], list):
                        for noncurrentVersionTransition in item['noncurrentVersionTransition']:
                            self._transNoncurrentVersionTransition(ruleEle, noncurrentVersionTransition)
                    else:
                        self._transNoncurrentVersionTransition(ruleEle, item['noncurrentVersionTransition'])

                if item.get('noncurrentVersionExpiration') is not None and item['noncurrentVersionExpiration'].get(
                        'noncurrentDays') is not None:
                    noncurrentVersionExpirationEle = ET.SubElement(ruleEle, 'NoncurrentVersionExpiration')
                    ET.SubElement(noncurrentVersionExpirationEle, 'NoncurrentDays').text = util.to_string(
                        item['noncurrentVersionExpiration']['noncurrentDays'])

        return ET.tostring(root, 'UTF-8')

    def _trans_lifecycle_transition_expiration(self, item, ruleEle):
        if item.get('transition') is not None:
            _transition = item['transition']
            if isinstance(_transition, list):
                for transition in _transition:
                    self._transTransition(ruleEle, transition)
            else:
                self._transTransition(ruleEle, _transition)

        if item.get('expiration') is not None and (
                item['expiration'].get('date') is not None or item['expiration'].get('days') is not None):
            expirationEle = ET.SubElement(ruleEle, 'Expiration')
            if item['expiration'].get('days') is not None:
                ET.SubElement(expirationEle, 'Days').text = util.to_string(item['expiration']['days'])
            elif item['expiration'].get('date') is not None:
                date = item['expiration']['date'].ToUTMidTime() if isinstance(item['expiration']['date'],
                                                                              DateTime) else item['expiration'][
                    'date']
                ET.SubElement(expirationEle, 'Date').text = util.to_string(date)
        return ruleEle

    def trans_website(self, website):
        root = ET.Element('WebsiteConfiguration')
        if website.get('redirectAllRequestTo') is not None:
            redirectAllEle = ET.SubElement(root, 'RedirectAllRequestsTo')
            if website['redirectAllRequestTo'].get('hostName') is not None:
                ET.SubElement(redirectAllEle, 'HostName').text = util.to_string(
                    website['redirectAllRequestTo']['hostName'])
            if website['redirectAllRequestTo'].get('protocol') is not None:
                ET.SubElement(redirectAllEle, 'Protocol').text = util.to_string(
                    website['redirectAllRequestTo']['protocol'])
        else:
            if website.get('indexDocument') is not None and website['indexDocument'].get('suffix') is not None:
                indexDocEle = ET.SubElement(root, 'IndexDocument')
                ET.SubElement(indexDocEle, 'Suffix').text = util.to_string(website['indexDocument']['suffix'])
            if website.get('errorDocument') is not None and website['errorDocument'].get('key') is not None:
                errorDocEle = ET.SubElement(root, 'ErrorDocument')
                ET.SubElement(errorDocEle, 'Key').text = util.to_string(website['errorDocument']['key'])
            root = self._trans_website_routingRules(root, website)
        return ET.tostring(root, 'UTF-8')

    @staticmethod
    def _trans_website_routingRules(root, website):
        if isinstance(website.get('routingRules'), list) and bool(website['routingRules']):
            routingRulesEle = ET.SubElement(root, 'RoutingRules')
            for routingRule in website['routingRules']:
                routingRuleEle = ET.SubElement(routingRulesEle, 'RoutingRule')
                if routingRule.get('condition') is not None:
                    conditionEle = ET.SubElement(routingRuleEle, 'Condition')
                    if routingRule['condition'].get('keyPrefixEquals') is not None:
                        ET.SubElement(conditionEle, 'KeyPrefixEquals').text = util.to_string(
                            routingRule['condition']['keyPrefixEquals'])
                    if routingRule['condition'].get('httpErrorCodeReturnedEquals') is not None:
                        ET.SubElement(conditionEle, 'HttpErrorCodeReturnedEquals').text = util.to_string(
                            routingRule['condition']['httpErrorCodeReturnedEquals'])

                if routingRule.get('redirect') is not None:
                    redirectEle = ET.SubElement(routingRuleEle, 'Redirect')
                    redirect = routingRule['redirect']
                    if redirect.get('protocol') is not None:
                        ET.SubElement(redirectEle, 'Protocol').text = util.to_string(redirect['protocol'])

                    if redirect.get('hostName') is not None:
                        ET.SubElement(redirectEle, 'HostName').text = util.to_string(redirect['hostName'])

                    if redirect.get('replaceKeyPrefixWith') is not None:
                        ET.SubElement(redirectEle, 'ReplaceKeyPrefixWith').text = util.safe_decode(
                            redirect['replaceKeyPrefixWith'])

                    if redirect.get('replaceKeyWith') is not None:
                        ET.SubElement(redirectEle, 'ReplaceKeyWith').text = util.safe_decode(
                            redirect['replaceKeyWith'])

                    if redirect.get('httpRedirectCode') is not None:
                        ET.SubElement(redirectEle, 'HttpRedirectCode').text = util.to_string(
                            redirect['httpRedirectCode'])
        return root

    def trans_notification(self, notification):
        root = ET.Element('NotificationConfiguration')

        def _set_configuration(config_type, urn_type):
            if notification is not None and bool(notification) and notification.get(config_type) is not None and bool(
                    notification[config_type]):
                node = config_type[:1].upper() + config_type[1:-1]
                for topicConfiguration in notification[config_type]:
                    topicConfigurationEle = ET.SubElement(root, node)
                    if topicConfiguration.get('id') is not None:
                        ET.SubElement(topicConfigurationEle, 'Id').text = util.safe_decode(topicConfiguration['id'])

                    if isinstance(topicConfiguration.get('filterRules'), list) and bool(
                            topicConfiguration['filterRules']):
                        filterEle = ET.SubElement(topicConfigurationEle, 'Filter')
                        filterRulesEle = ET.SubElement(filterEle, 'Object' if self.is_obs else 'S3Key')
                        for filterRule in topicConfiguration['filterRules']:
                            filterRuleEle = ET.SubElement(filterRulesEle, 'FilterRule')
                            if filterRule.get('name') is not None:
                                ET.SubElement(filterRuleEle, 'Name').text = util.to_string(filterRule['name'])
                            if filterRule.get('value') is not None:
                                ET.SubElement(filterRuleEle, 'Value').text = util.safe_decode(filterRule['value'])
                    _urn_type = urn_type[:1].upper() + urn_type[1:]
                    if topicConfiguration.get(urn_type) is not None:
                        ET.SubElement(topicConfigurationEle, _urn_type).text = util.to_string(
                            topicConfiguration[urn_type])

                    if isinstance(topicConfiguration.get('events'), list) and len(topicConfiguration['events']) > 0:
                        for event in topicConfiguration['events']:
                            ET.SubElement(topicConfigurationEle, 'Event').text = util.to_string(
                                self.ha.adapt_event_type(event))

        _set_configuration('topicConfigurations', 'topic')
        _set_configuration('functionGraphConfigurations', 'functionGraph')

        return ET.tostring(root, 'UTF-8')

    @staticmethod
    def trans_complete_multipart_upload_request(completeMultipartUploadRequest):
        root = ET.Element('CompleteMultipartUpload')
        parts = [] if completeMultipartUploadRequest.get('parts') is None else (
            sorted(completeMultipartUploadRequest['parts'], key=lambda d: d.partNum))
        for obj in parts:
            partEle = ET.SubElement(root, 'Part')
            ET.SubElement(partEle, 'PartNumber').text = util.to_string(obj.get('partNum'))
            ET.SubElement(partEle, 'ETag').text = util.to_string(obj.get('etag'))
        return ET.tostring(root, 'UTF-8')

    def trans_restore_object(self, **kwargs):
        pathArgs = {'restore': None}
        self._put_key_value(pathArgs, const.VERSION_ID_PARAM, kwargs.get('versionId'))
        entity = self.trans_restore(days=kwargs.get('days'), tier=kwargs.get('tier'))
        headers = {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))}
        return {'pathArgs': pathArgs, 'headers': headers, 'entity': entity}

    def trans_set_bucket_acl(self, **kwargs):
        headers = {}
        aclControl = kwargs.get('aclControl')
        if aclControl is not None:
            self._put_key_value(headers, self.ha.acl_header(), self.ha.adapt_acl_control(aclControl))
            entity = None
        else:
            acl = kwargs.get('acl')
            entity = None if acl is None or len(acl) == 0 else self.trans_acl(acl)
        return {'pathArgs': {'acl': None}, 'headers': headers, 'entity': entity}

    def trans_set_object_acl(self, **kwargs):
        pathArgs = {'acl': None}
        versionId = kwargs.get('versionId')
        if versionId:
            pathArgs[const.VERSION_ID_PARAM] = util.to_string(versionId)

        headers = {}
        aclControl = kwargs.get('aclControl')
        if aclControl is not None:
            self._put_key_value(headers, self.ha.acl_header(), self.ha.adapt_acl_control(aclControl))
            entity = None
        else:
            acl = kwargs.get('acl')
            entity = None if acl is None or not bool(acl) else self.trans_acl(acl, False)
        return {'pathArgs': pathArgs, 'headers': headers, 'entity': entity}

    def trans_acl(self, acl, is_bucket=True):
        root = ET.Element('AccessControlPolicy')
        if acl.get('owner') is not None:
            ownerEle = ET.SubElement(root, 'Owner')
            owner = acl['owner']
            ET.SubElement(ownerEle, 'ID').text = util.to_string(owner.get('owner_id'))
            if owner.get('owner_name') is not None and not self.is_obs:
                ET.SubElement(ownerEle, 'DisplayName').text = util.safe_decode(owner['owner_name'])

        if not is_bucket and self.is_obs and acl.get('delivered') is not None:
            ET.SubElement(root, 'Delivered').text = util.to_string(acl['delivered']).lower()

        grants = acl.get('grants')
        if grants is not None and len(grants) > 0:
            aclEle = ET.SubElement(root, 'AccessControlList')
            self.trans_grantee(aclEle, grants)
        return ET.tostring(root, 'UTF-8')

    def trans_grantee(self, aclEle, grants):
        for grant in grants:
            grantEle = ET.SubElement(aclEle, 'Grant')
            if grant.get('grantee') is not None:
                attrib = {'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance'}
                grantee = grant['grantee']
                if grantee.get('group') is not None:
                    attrib['xsi:type'] = 'Group'
                    group_val = self.ha.adapt_group(util.to_string(grantee['group']))
                    if group_val:
                        granteeEle = ET.SubElement(grantEle, 'Grantee', self._trans_grantee_is_obs(attrib))
                        ET.SubElement(granteeEle, 'Canned' if self.is_obs else 'URI').text = group_val
                    else:
                        aclEle.remove(grantEle)
                        continue
                elif grantee.get('grantee_id') is not None:
                    attrib['xsi:type'] = 'CanonicalUser'
                    granteeEle = ET.SubElement(grantEle, 'Grantee', self._trans_grantee_is_obs(attrib))
                    ET.SubElement(granteeEle, 'ID').text = util.to_string(grantee['grantee_id'])
                    if grantee.get('grantee_name') is not None and not self.is_obs:
                        ET.SubElement(granteeEle, 'DisplayName').text = util.safe_decode(grantee['grantee_name'])
            if grant.get('permission') is not None:
                ET.SubElement(grantEle, 'Permission').text = util.to_string(grant['permission'])

            if grant.get('delivered') is not None and self.is_obs:
                ET.SubElement(grantEle, 'Delivered').text = util.to_string(grant['delivered']).lower()

    def _trans_grantee_is_obs(self, attrib):
        return {} if self.is_obs else attrib

    def trans_logging(self, logging):
        root = ET.Element('BucketLoggingStatus')
        if self.is_obs and logging.get('agency') is not None:
            ET.SubElement(root, 'Agency').text = util.to_string(logging['agency'])
        if logging.get('targetBucket') is not None or logging.get('targetPrefix') is not None or (
                logging.get('targetGrants') is not None and bool(logging['targetGrants'])):
            loggingEnableEle = ET.SubElement(root, 'LoggingEnabled')
            if logging.get('targetBucket') is not None:
                ET.SubElement(loggingEnableEle, 'TargetBucket').text = util.to_string(logging['targetBucket'])
            if logging.get('targetPrefix') is not None:
                ET.SubElement(loggingEnableEle, 'TargetPrefix').text = util.safe_decode(logging['targetPrefix'])
            if logging.get('targetGrants') is not None and len(logging['targetGrants']) > 0:
                grantsEle = ET.SubElement(loggingEnableEle, 'TargetGrants')
                self.trans_grantee(grantsEle, logging['targetGrants'])
        return ET.tostring(root, 'UTF-8')

    def trans_restore(self, days, tier):
        root = ET.Element('RestoreRequest')
        ET.SubElement(root, 'Days').text = util.to_string(days)
        tier = self.ha.adapt_restore_tier(tier)
        if tier is not None:
            glacierJobEle = ET.SubElement(root, 'RestoreJob') if self.is_obs else ET.SubElement(root,
                                                                                                'GlacierJobParameters')
            ET.SubElement(glacierJobEle, 'Tier').text = util.to_string(tier)
        return ET.tostring(root, 'UTF-8')

    def trans_put_object(self, **kwargs):
        _headers = {}
        metadata = kwargs.get('metadata')
        headers = kwargs.get('headers')
        if metadata is not None:
            for k, v in metadata.items():
                if not util.to_string(k).lower().startswith(self.ha._get_header_prefix()):
                    k = self.ha._get_meta_header_prefix() + k
                self._put_key_value(_headers, k, v)
        if headers is not None and len(headers) > 0:
            self._put_key_value(_headers, const.CONTENT_MD5_HEADER, headers.get('md5'))
            self._put_key_value(_headers, self.ha.content_sha256_header(), headers.get('sha256'))
            self._put_key_value(_headers, self.ha.acl_header(), self.ha.adapt_acl_control(headers.get('acl')))
            self._put_key_value(_headers, self.ha.website_redirect_location_header(), headers.get('location'))
            self._put_key_value(_headers, const.CONTENT_TYPE_HEADER, headers.get('contentType'))
            self._set_sse_header(headers.get('sseHeader'), _headers)
            self._put_key_value(_headers, self.ha.storage_class_header(),
                                self.ha.adapt_storage_class(headers.get('storageClass')))
            self._put_key_value(_headers, const.CONTENT_LENGTH_HEADER, headers.get('contentLength'))
            self._put_key_value(_headers, self.ha.expires_header(), headers.get('expires'))

            if self.is_obs:
                self._put_key_value(_headers, self.ha.success_action_redirect_header(),
                                    headers.get('successActionRedirect'))

            if headers.get('extensionGrants') is not None and len(headers['extensionGrants']) > 0:
                grantDict = {}
                for extensionGrant in headers['extensionGrants']:
                    permission = self.ha.adapt_extension_permission(extensionGrant.get('permission'), False)
                    if permission is not None and extensionGrant.get('granteeId') is not None:
                        granteeIds = grantDict.get(permission)
                        if granteeIds is None:
                            granteeIds = set()
                            grantDict[permission] = granteeIds
                        granteeIds.add('id=%s' % util.to_string(extensionGrant['granteeId']))

                for key, value in grantDict.items():
                    self._put_key_value(_headers, key, ','.join(value))
        return _headers

    def trans_initiate_multipart_upload(self, **kwargs):
        pathArgs = {'uploads': None}
        self._put_key_value(pathArgs, "encoding-type", kwargs.get('encoding_type'))
        headers = {}
        self._put_key_value(headers, self.ha.acl_header(), self.ha.adapt_acl_control(kwargs.get('acl')))
        self._put_key_value(headers, self.ha.storage_class_header(),
                            self.ha.adapt_storage_class(kwargs.get('storageClass')))
        metadata = kwargs.get('metadata')
        if metadata is not None:
            for k, v in metadata.items():
                if not util.to_string(k).lower().startswith(self.ha._get_header_prefix()):
                    k = self.ha._get_meta_header_prefix() + k
                self._put_key_value(headers, k, v)
        self._put_key_value(headers, self.ha.website_redirect_location_header(), kwargs.get('websiteRedirectLocation'))
        self._put_key_value(headers, const.CONTENT_TYPE_HEADER, kwargs.get('contentType'))
        self._put_key_value(headers, self.ha.expires_header(), kwargs.get('expires'))
        self._set_sse_header(kwargs.get('sseHeader'), headers)

        extensionGrants = kwargs.get('extensionGrants')
        if extensionGrants is not None and len(extensionGrants) > 0:
            grantDict = {}
            for extensionGrant in extensionGrants:
                permission = self.ha.adapt_extension_permission(extensionGrant.get('permission'), False)
                if permission is not None and extensionGrant.get('granteeId') is not None:
                    granteeIds = grantDict.get(permission)
                    if granteeIds is None:
                        granteeIds = set()
                        grantDict[permission] = granteeIds
                    granteeIds.add('id=%s' % util.to_string(extensionGrant['granteeId']))

            for key, value in grantDict.items():
                self._put_key_value(headers, key, ','.join(value))
        return {'pathArgs': pathArgs, 'headers': headers}

    def trans_set_object_metadata(self, **kwargs):
        versionId = kwargs.get('versionId')
        pathArgs = {'metadata': None}
        if versionId is not None:
            pathArgs[const.VERSION_ID_PARAM] = util.to_string(versionId)

        _headers = {}
        metadata = kwargs.get('metadata')
        if metadata is not None:
            for k, v in metadata.items():
                if not util.to_string(k).lower().startswith(self.ha._get_header_prefix()):
                    k = self.ha._get_meta_header_prefix() + k
                self._put_key_value(_headers, k, v)

        headers = kwargs.get('headers')
        if headers is not None and len(headers) > 0:
            directive = 'REPLACE_NEW' if headers.get('removeUnset') is None or not headers['removeUnset'] else 'REPLACE'
            self._put_key_value(_headers, self.ha.metadata_directive_header(), directive)
            self._put_key_value(_headers, self.ha.storage_class_header(),
                                self.ha.adapt_storage_class(headers.get('storageClass')))
            self._put_key_value(_headers, self.ha.website_redirect_location_header(), headers.get('location'))
            self._put_key_value(_headers, const.CACHE_CONTROL_HEADER, headers.get('cacheControl'))
            self._put_key_value(_headers, const.CONTENT_DISPOSITION_HEADER, headers.get('contentDisposition'))
            self._put_key_value(_headers, const.CONTENT_ENCODING_HEADER, headers.get('contentEncoding'))
            self._put_key_value(_headers, const.CONTENT_LANGUAGE_HEADER, headers.get('contentLanguage'))
            self._put_key_value(_headers, const.CONTENT_TYPE_HEADER, headers.get('contentType'))
            self._put_key_value(_headers, const.EXPIRES_HEADER, headers.get('expires'))

        return {'pathArgs': pathArgs, 'headers': _headers}

    def trans_copy_object(self, **kwargs):
        _headers = self._trans_copy_object_handle_metadata(kwargs)
        copy_source = '/%s/%s' % (
            util.to_string(kwargs.get('sourceBucketName')), util.to_string(kwargs.get('sourceObjectKey')))
        versionId = kwargs.get('versionId')
        if versionId is not None:
            copy_source = '%s?versionId=%s' % (copy_source, versionId)
        _headers[self.ha.copy_source_header()] = copy_source

        headers = kwargs.get('headers')
        if headers is not None and len(headers) > 0:
            self._put_key_value(_headers, self.ha.acl_header(), self.ha.adapt_acl_control(headers.get('acl')))
            self._put_key_value(_headers, self.ha.storage_class_header(),
                                self.ha.adapt_storage_class(headers.get('storageClass')))

            self._put_key_value(_headers, self.ha.metadata_directive_header(), headers.get('directive'))
            self._put_key_value(_headers, self.ha.copy_source_if_match_header(), headers.get('if_match'))
            self._put_key_value(_headers, self.ha.copy_source_if_none_match_header(), headers.get('if_none_match'))
            self._put_key_value(_headers, self.ha.copy_source_if_modified_since_header(),
                                headers['if_modified_since'].ToGMTTime() if isinstance(headers.get('if_modified_since'),
                                                                                       DateTime) else headers.get(
                                    'if_modified_since'))
            self._put_key_value(_headers, self.ha.copy_source_if_unmodified_since_header(),
                                headers['if_unmodified_since'].ToGMTTime() if isinstance(
                                    headers.get('if_unmodified_since'), DateTime) else headers.get(
                                    'if_unmodified_since'))

            self._put_key_value(_headers, self.ha.website_redirect_location_header(), headers.get('location'))
            self._put_key_value(_headers, const.CACHE_CONTROL_HEADER, headers.get('cacheControl'))
            self._put_key_value(_headers, const.CONTENT_DISPOSITION_HEADER, headers.get('contentDisposition'))

            self._put_key_value(_headers, const.CONTENT_ENCODING_HEADER, headers.get('contentEncoding'))
            self._put_key_value(_headers, const.CONTENT_LANGUAGE_HEADER, headers.get('contentLanguage'))
            self._put_key_value(_headers, const.CONTENT_TYPE_HEADER, headers.get('contentType'))
            self._put_key_value(_headers, const.EXPIRES_HEADER, headers.get('expires'))

            self._set_sse_header(headers.get('destSseHeader'), _headers)
            self._set_source_sse_header(headers.get('sourceSseHeader'), _headers)

            if self.is_obs:
                self._put_key_value(_headers, self.ha.success_action_redirect_header(),
                                    headers.get('successActionRedirect'))

            if headers.get('extensionGrants') is not None:
                grantDict = {}
                for extensionGrant in headers['extensionGrants']:
                    permission = self.ha.adapt_extension_permission(extensionGrant.get('permission'), False)
                    if permission is not None and extensionGrant.get('granteeId') is not None:
                        granteeIds = grantDict.get(permission)
                        if granteeIds is None:
                            granteeIds = set()
                            grantDict[permission] = granteeIds
                        granteeIds.add('id=%s' % util.to_string(extensionGrant['granteeId']))

                for key, value in grantDict.items():
                    self._put_key_value(_headers, key, ','.join(value))

        return {'headers': _headers}

    def _trans_copy_object_handle_metadata(self, kwargs):
        _headers = {}
        metadata = kwargs.get('metadata')
        if metadata is not None:
            for k, v in metadata.items():
                if not util.to_string(k).lower().startswith(self.ha._get_header_prefix()):
                    k = self.ha._get_meta_header_prefix() + k
                self._put_key_value(_headers, k, v)
        return _headers

    def trans_copy_part(self, **kwargs):
        headers = {}
        headers[self.ha.copy_source_header()] = util.to_string(kwargs.get('copySource'))
        copySourceRange = kwargs.get('copySourceRange')
        if copySourceRange is not None:
            copySourceRange = util.to_string(copySourceRange)
            self._put_key_value(headers, self.ha.copy_source_range_header(),
                                copySourceRange if copySourceRange.startswith('bytes=') else 'bytes=' + copySourceRange)
        self._set_sse_header(kwargs.get('destSseHeader'), headers)
        self._set_source_sse_header(kwargs.get('sourceSseHeader'), headers)

        return {'headers': headers,
                'pathArgs': {'partNumber': kwargs.get('partNumber'), 'uploadId': kwargs.get('uploadId')}}

    def trans_get_object(self, **kwargs):
        pathArgs = {}
        getObjectRequest = kwargs.get('getObjectRequest')
        if getObjectRequest is not None and len(getObjectRequest) > 0:
            self._put_key_value(pathArgs, const.RESPONSE_CACHE_CONTROL_PARAM, getObjectRequest.get('cache_control'))
            self._put_key_value(pathArgs, const.RESPONSE_CONTENT_DISPOSITION_PARAM,
                                getObjectRequest.get('content_disposition'))
            self._put_key_value(pathArgs, const.RESPONSE_CONTENT_ENCODING_PARAM,
                                getObjectRequest.get('content_encoding'))
            self._put_key_value(pathArgs, const.RESPONSE_CONTENT_LANGUAGE_PARAM,
                                getObjectRequest.get('content_language'))
            self._put_key_value(pathArgs, const.RESPONSE_CONTENT_TYPE_PARAM, getObjectRequest.get('content_type'))
            self._put_key_value(pathArgs, const.RESPONSE_EXPIRES_PARAM, getObjectRequest.get('expires'))
            self._put_key_value(pathArgs, const.VERSION_ID_PARAM, getObjectRequest.get('versionId'))
            self._put_key_value(pathArgs, const.X_IMAGE_PROCESS_PARAM, getObjectRequest.get('imageProcess'))

        _headers = {}
        headers = kwargs.get('headers')
        if headers is not None and len(headers) > 0:
            if headers.get('range') is not None:
                _range = util.to_string(headers['range'])
                self._put_key_value(_headers, const.RANGE_HEADER,
                                    _range if _range.startswith('bytes=') else 'bytes=' + _range)
            self._put_key_value(_headers, const.IF_MODIFIED_SINCE,
                                headers['if_modified_since'].ToGMTTime() if isinstance(headers.get('if_modified_since'),
                                                                                       DateTime) else headers.get(
                                    'if_modified_since'))
            self._put_key_value(_headers, const.IF_UNMODIFIED_SINCE,
                                headers['if_unmodified_since'].ToGMTTime() if isinstance(
                                    headers.get('if_unmodified_since'), DateTime) else headers.get(
                                    'if_unmodified_since'))
            self._put_key_value(_headers, const.IF_MATCH, headers.get('if_match'))
            self._put_key_value(_headers, const.IF_NONE_MATCH, headers.get('if_none_match'))
            self._put_key_value(_headers, const.ORIGIN_HEADER, headers.get('origin'))
            self._put_key_value(_headers, const.ACCESS_CONTROL_REQUEST_HEADERS_HEADER, headers.get('requestHeaders'))
            self._set_sse_header(headers.get('sseHeader'), _headers, True)
        return {'pathArgs': pathArgs, 'headers': _headers}

    def trans_list_multipart_uploads(self, **kwargs):
        pathArgs = {'uploads': None}
        self._put_key_value(pathArgs, 'encoding-type', kwargs.get('encoding_type'))
        multipart = kwargs.get('multipart')
        if multipart is not None:
            self._put_key_value(pathArgs, 'delimiter', multipart.get('delimiter'))
            self._put_key_value(pathArgs, 'prefix', multipart.get('prefix'))
            self._put_key_value(pathArgs, 'max-uploads', multipart.get('max_uploads'))
            self._put_key_value(pathArgs, 'key-marker', multipart.get('key_marker'))
            self._put_key_value(pathArgs, 'upload-id-marker', multipart.get('upload_id_marker'))
        return {'pathArgs': pathArgs}

    def _set_source_sse_header(self, sseHeader, headers=None):
        if headers is None:
            headers = {}
        if isinstance(sseHeader, SseCHeader):
            self._put_key_value(headers, self.ha.copy_source_sse_c_header(), sseHeader.get('encryption'))
            key = util.to_string(sseHeader.get('key'))
            self._put_key_value(headers, self.ha.copy_source_sse_c_key_header(), util.base64_encode(key))
            self._put_key_value(headers, self.ha.copy_source_sse_c_key_md5_header(),
                                util.base64_encode(util.md5_encode(key)))
        return headers

    def _set_sse_header(self, sseHeader, headers=None, onlySseCHeader=False):
        if headers is None:
            headers = {}
        if isinstance(sseHeader, SseCHeader):
            self._put_key_value(headers, self.ha.sse_c_header(), sseHeader.get('encryption'))
            key = util.to_string(sseHeader.get('key'))
            self._put_key_value(headers, self.ha.sse_c_key_header(), util.base64_encode(key))
            self._put_key_value(headers, self.ha.sse_c_key_md5_header(), util.base64_encode(util.md5_encode(key)))
        elif isinstance(sseHeader, SseKmsHeader) and not onlySseCHeader:
            self._put_key_value(headers, self.ha.sse_kms_header(),
                                sseHeader.get('encryption') if self.is_obs else 'aws:' + util.to_string(
                                    sseHeader.get('encryption')))
            if sseHeader.get('key') is not None:
                self._put_key_value(headers, self.ha.sse_kms_key_header(), sseHeader['key'])
        return headers

    def trans_set_bucket_replication(self, **kwargs):
        entity = self.trans_replication(kwargs.get('replication'))
        headers = {const.CONTENT_MD5_HEADER: util.base64_encode(util.md5_encode(entity))}
        return {'pathArgs': {'replication': None}, 'headers': headers, 'entity': entity}

    def trans_replication(self, replication):
        root = ET.Element('ReplicationConfiguration')
        if self.is_obs and replication.get('agency') is not None:
            ET.SubElement(root, 'Agency').text = util.to_string(replication['agency'])

        if replication.get('replicationRules') is not None:
            for replicationRule in replication['replicationRules']:
                ruleEle = ET.SubElement(root, 'Rule')
                if replicationRule.get('id') is not None:
                    ET.SubElement(ruleEle, 'ID').text = util.safe_decode(replicationRule['id'])
                if replicationRule.get('prefix') is not None:
                    ET.SubElement(ruleEle, 'Prefix').text = util.safe_decode(replicationRule['prefix'])
                if replicationRule.get('status') is not None:
                    ET.SubElement(ruleEle, 'Status').text = util.to_string(replicationRule['status'])
                if replicationRule.get('historicalObjectReplication') is not None:
                    ET.SubElement(ruleEle, 'HistoricalObjectReplication').text = util.to_string(
                        replicationRule['historicalObjectReplication'])

                if replicationRule.get('bucket') is not None:
                    destinationEle = ET.SubElement(ruleEle, 'Destination')
                    bucket_name = util.to_string(replicationRule['bucket'])
                    bucket_name = bucket_name if self.is_obs else bucket_name if bucket_name.startswith(
                        'arn:aws:s3:::') else 'arn:aws:s3:::' + bucket_name
                    ET.SubElement(destinationEle, 'Bucket').text = bucket_name

                    if replicationRule.get('storageClass') is not None:
                        ET.SubElement(destinationEle, 'StorageClass').text = self.ha.adapt_storage_class(
                            replicationRule['storageClass'])

                    if replicationRule.get('deleteData') is not None:
                        ET.SubElement(destinationEle, 'DeleteData').text = util.to_string(replicationRule['deleteData'])
        return ET.tostring(root, 'UTF-8')

    @staticmethod
    def trans_bucket_request_payment(payer):
        root = ET.Element('RequestPaymentConfiguration')
        ET.SubElement(root, 'Payer').text = util.to_string(payer)
        return ET.tostring(root, 'UTF-8')

    def trans_get_extension_headers(self, headers):
        _headers = {}
        if headers is not None and len(headers) > 0:
            self._put_key_value(_headers, self.ha.request_payer_header(), headers.get('requesterPayer'))
            self._put_key_value(_headers, self.ha.location_clustergroup_id_header(),
                                headers.get('locationClusterGroupId'))
        return _headers

    # OEF trans func
    def trans_set_bucket_fetch_policy(self, fetchPolicy):
        headers = {}
        self._put_key_value(headers, const.CONTENT_TYPE_HEADER, const.MIME_TYPES.get("json"))
        self._put_key_value(headers, self.ha.oef_marker_header(), "yes")
        jsonPolicy = {"fetch": fetchPolicy}
        entity = json.dumps(jsonPolicy, ensure_ascii=False)
        return {'headers': headers, 'entity': entity}

    def trans_set_bucket_fetch_job(self, fetchJob):
        headers = {}
        self._put_key_value(headers, const.CONTENT_TYPE_HEADER, const.MIME_TYPES.get("json"))
        self._put_key_value(headers, self.ha.oef_marker_header(), "yes")
        if fetchJob.get("objectheaders") is not None:
            for k in list(fetchJob["objectheaders"].keys()):
                v = fetchJob["objectheaders"].get(k)
                if v is not None:
                    if not util.to_string(k).lower().startswith(self.ha._get_header_prefix()):
                        del fetchJob["objectheaders"][k]
                        k = self.ha._get_meta_header_prefix() + k
                    fetchJob["objectheaders"][k] = v
                else:
                    del fetchJob["objectheaders"][k]
        entity = json.dumps(fetchJob, ensure_ascii=False)
        return {'headers': headers, 'entity': entity}

    @staticmethod
    def _find_item(root, item_name, encoding_type=None):
        result = root.find(item_name)
        if result is None:
            return None
        result = result.text
        if result is None:
            return None
        if const.IS_PYTHON2:
            result = util.safe_encode(result)
        if encoding_type == "url":
            return util.to_string(unquote_plus(result))
        return util.to_string(result)

    @staticmethod
    def _find_text(result, encoding_type=None):
        if result is None:
            return None
        if const.IS_PYTHON2:
            result = util.safe_encode(result)
        if encoding_type == "url":
            return util.to_string(unquote_plus(result))
        return util.to_string(result)

    def parseListBuckets(self, xml, headers=None):
        root = ET.fromstring(xml)
        owner = root.find('Owner')
        Owners = None
        if owner is not None:
            ID = self._find_item(owner, 'ID')
            DisplayName = None if self.is_obs else self._find_item(owner, 'DisplayName')
            Owners = Owner(owner_id=ID, owner_name=DisplayName)

        buckets = root.find('Buckets').findall('Bucket')
        entries = []

        for bucket in buckets:
            name = self._find_item(bucket, 'Name')
            d = self._find_item(bucket, 'CreationDate')
            location = self._find_item(bucket, 'Location')
            bucket_type = self._find_item(bucket, 'BucketType')
            create_date = DateTime.UTCToLocal(d)
            curr_bucket = Bucket(name=name, create_date=create_date, location=location, bucket_type=bucket_type)
            entries.append(curr_bucket)
        return ListBucketsResponse(buckets=entries, owner=Owners)

    def parseErrorResult(self, xml, headers=None):
        root = ET.fromstring(xml)
        code = self._find_item(root, 'Code')
        message = self._find_item(root, 'Message')
        requestId = self._find_item(root, 'RequestId')
        hostId = self._find_item(root, 'HostId')
        resource = self._find_item(root, 'Resource')
        return code, message, requestId, hostId, resource

    def parseListObjects(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        name = self._find_item(root, 'Name')
        prefix = self._find_item(root, 'Prefix', encoding_type)
        marker = self._find_item(root, 'Marker', encoding_type)
        delimiter = self._find_item(root, 'Delimiter', encoding_type)
        max_keys = self._find_item(root, 'MaxKeys')
        is_truncated = self._find_item(root, 'IsTruncated')
        next_marker = self._find_item(root, 'NextMarker', encoding_type)

        key_entries = []
        contents = root.findall('Contents')
        if contents is not None:
            for node in contents:
                key = self._find_item(node, 'Key', encoding_type)
                lastmodified = self._find_item(node, 'LastModified')
                etag = self._find_item(node, 'ETag')
                size = self._find_item(node, 'Size')
                storage = self._find_item(node, 'StorageClass')
                owner = node.find('Owner')
                Owners = None
                if owner is not None:
                    ID = self._find_item(owner, 'ID')
                    DisplayName = None if self.is_obs else self._find_item(owner, 'DisplayName')
                    Owners = Owner(owner_id=ID, owner_name=DisplayName)
                isAppendable = self._find_item(node, 'Type')
                key_entry = Content(key=key, lastModified=DateTime.UTCToLocal(lastmodified), etag=etag,
                                    size=util.to_long(size), owner=Owners, storageClass=storage,
                                    isAppendable=isAppendable == 'Appendable')
                key_entries.append(key_entry)

        common_prefixes = []
        prefixes = root.findall('CommonPrefixes')
        if prefixes is not None:
            for p in prefixes:
                pre = self._find_item(p, 'Prefix', encoding_type)
                commonprefix = CommonPrefix(prefix=pre)
                common_prefixes.append(commonprefix)

        location = headers.get(self.ha.bucket_region_header())
        return ListObjectsResponse(name=name, location=location, prefix=prefix, marker=marker, delimiter=delimiter,
                                   max_keys=util.to_int(max_keys),
                                   is_truncated=util.to_bool(is_truncated), next_marker=next_marker,
                                   contents=key_entries, commonPrefixs=common_prefixes, encoding_type=encoding_type)

    def parseGetBucketMetadata(self, headers):
        option = GetBucketMetadataResponse()
        option.accessContorlAllowOrigin = headers.get('access-control-allow-origin')
        option.accessContorlAllowHeaders = headers.get('access-control-allow-headers')
        option.accessContorlAllowMethods = headers.get('access-control-allow-methods')
        option.accessContorlExposeHeaders = headers.get('access-control-expose-headers')
        option.accessContorlMaxAge = util.to_int(headers.get('access-control-max-age'))
        option.storageClass = headers.get(self.ha.default_storage_class_header())
        option.location = headers.get(self.ha.bucket_region_header())
        option.obsVersion = headers.get(self.ha.server_version_header())
        option.availableZone = headers.get(self.ha.az_redundancy_header())
        option.epid = headers.get(self.ha.epid_header())
        return option

    def parseGetBucketLocation(self, xml, headers=None):
        root = ET.fromstring(xml)
        location = root.text if self.is_obs else self._find_item(root, 'LocationConstraint')
        return LocationResponse(location=location)

    def parseGetBucketStorageInfo(self, xml, headers=None):
        root = ET.fromstring(xml)
        size = self._find_item(root, 'Size')
        objectNumber = self._find_item(root, 'ObjectNumber')
        return GetBucketStorageInfoResponse(size=util.to_long(size), objectNumber=util.to_int(objectNumber))

    @staticmethod
    def parseGetBucketPolicy(json_str, headers=None):
        return Policy(policyJSON=json_str)

    def parseGetBucketStoragePolicy(self, xml, headers=None):
        root = ET.fromstring(xml)
        storageClass = root.text if self.is_obs else self._find_item(root, 'DefaultStorageClass')
        return GetBucketStoragePolicyResponse(storageClass=storageClass)

    def parseGetBucketQuota(self, xml, headers=None):
        root = ET.fromstring(xml)
        quota = self._find_item(root, 'StorageQuota')
        return GetBucketQuotaResponse(quota=util.to_long(quota))

    def parseGetBucketEncryption(self, xml, headers=None):
        result = GetBucketEncryptionResponse()
        root = ET.fromstring(xml)
        sse = root.find('Rule/ApplyServerSideEncryptionByDefault')
        if sse:
            encryption = self._find_item(sse, 'SSEAlgorithm')
            result.encryption = encryption.replace('aws:', '')
            result.key = self._find_item(sse, 'KMSMasterKeyID')

        return result

    @staticmethod
    def parseGetBucketTagging(xml, headers=None):
        result = TagInfo()
        root = ET.fromstring(xml)
        tags = root.findall('TagSet/Tag')
        if tags:
            for tag in tags:
                key = tag.find('Key')
                key = util.safe_encode(key.text) if key is not None else None
                value = tag.find('Value')
                value = util.safe_encode(value.text) if value is not None else None
                result.addTag(key, value)
        return result

    def parseGetBucketCors(self, xml, headers=None):
        root = ET.fromstring(xml)
        corsList = []
        rules = root.findall('CORSRule')
        if rules is not None:
            for rule in rules:
                _id = self._find_item(rule, 'ID')
                maxAgeSecond = rule.find('MaxAgeSeconds')
                maxAgeSecond = util.to_int(maxAgeSecond.text) if maxAgeSecond is not None else None

                method = rule.findall('AllowedMethod')
                allowMethod = []
                if method is not None:
                    for v in method:
                        allowMethod.append(util.to_string(v.text))
                allowedOrigin = []
                method = rule.findall('AllowedOrigin')
                if method is not None:
                    for v in method:
                        allowedOrigin.append(util.to_string(v.text))
                allowedHeader = []
                method = rule.findall('AllowedHeader')
                if method is not None:
                    for v in method:
                        allowedHeader.append(util.to_string(v.text))
                exposeHeader = []
                method = rule.findall('ExposeHeader')
                if method is not None:
                    for v in method:
                        exposeHeader.append(util.to_string(v.text))

                corsList.append(CorsRule(id=_id, allowedMethod=allowMethod, allowedOrigin=allowedOrigin,
                                         allowedHeader=allowedHeader, maxAgeSecond=maxAgeSecond,
                                         exposeHeader=exposeHeader))
        return corsList

    def parseListVersions(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        Name = self._find_item(root, 'Name')
        Prefix = self._find_item(root, 'Prefix', encoding_type)
        Delimiter = self._find_item(root, 'Delimiter', encoding_type)
        KeyMarker = self._find_item(root, 'KeyMarker', encoding_type)
        VersionIdMarker = self._find_item(root, 'VersionIdMarker')
        NextKeyMarker = self._find_item(root, 'NextKeyMarker', encoding_type)
        NextVersionIdMarker = self._find_item(root, 'NextVersionIdMarker')
        MaxKeys = self._find_item(root, 'MaxKeys')
        IsTruncated = self._find_item(root, 'IsTruncated')
        location = headers.get(self.ha.bucket_region_header())
        head = ObjectVersionHead(name=Name, location=location, prefix=Prefix, delimiter=Delimiter, keyMarker=KeyMarker,
                                 versionIdMarker=VersionIdMarker,
                                 nextKeyMarker=NextKeyMarker, nextVersionIdMarker=NextVersionIdMarker,
                                 maxKeys=util.to_int(MaxKeys),
                                 isTruncated=util.to_bool(IsTruncated), encoding_type=encoding_type)

        version_list = []
        versions = root.findall('Version')
        for version in versions:
            Key = self._find_item(version, 'Key', encoding_type)
            VersionId = self._find_item(version, 'VersionId')
            IsLatest = self._find_item(version, 'IsLatest')
            LastModified = self._find_item(version, 'LastModified')
            ETag = self._find_item(version, 'ETag')
            Size = self._find_item(version, 'Size')
            owner = version.find('Owner')
            Owners = None
            if owner is not None:
                ID = self._find_item(owner, 'ID')
                DisplayName = None if self.is_obs else self._find_item(owner, 'DisplayName')
                Owners = Owner(owner_id=ID, owner_name=DisplayName)
            StorageClass = self._find_item(version, 'StorageClass')
            isAppendable = self._find_item(version, 'Type')
            Version = ObjectVersion(key=Key, versionId=VersionId, isLatest=util.to_bool(IsLatest),
                                    lastModified=DateTime.UTCToLocal(LastModified), etag=ETag, size=util.to_long(Size),
                                    owner=Owners,
                                    storageClass=StorageClass, isAppendable=(isAppendable == 'Appendable'))
            version_list.append(Version)

        marker_list = []
        markers = root.findall('DeleteMarker')
        for marker in markers:
            Key = self._find_item(marker, 'Key', encoding_type)
            VersionId = self._find_item(marker, 'VersionId')
            IsLatest = self._find_item(marker, 'IsLatest')
            LastModified = self._find_item(marker, 'LastModified')
            owner = marker.find('Owner')
            Owners = None
            if owner is not None:
                ID = self._find_item(owner, 'ID')
                DisplayName = None if self.is_obs else self._find_item(owner, 'DisplayName')
                Owners = Owner(owner_id=ID, owner_name=DisplayName)
            Marker = ObjectDeleteMarker(key=Key, versionId=VersionId, isLatest=util.to_bool(IsLatest),
                                        lastModified=DateTime.UTCToLocal(LastModified), owner=Owners)
            marker_list.append(Marker)

        prefixes = root.findall('CommonPrefixes')
        prefix_list = []
        for prefix in prefixes:
            Prefix = self._find_item(prefix, 'Prefix', encoding_type)
            Pre = CommonPrefix(prefix=Prefix)
            prefix_list.append(Pre)
        return ObjectVersions(head=head, markers=marker_list, commonPrefixs=prefix_list, versions=version_list)

    @staticmethod
    def parseOptionsBucket(headers):
        option = OptionsResponse()
        option.accessContorlAllowOrigin = headers.get('access-control-allow-origin')
        option.accessContorlAllowHeaders = headers.get('access-control-allow-headers')
        option.accessContorlAllowMethods = headers.get('access-control-allow-methods')
        option.accessContorlExposeHeaders = headers.get('access-control-expose-headers')
        option.accessContorlMaxAge = util.to_int(headers.get('access-control-max-age'))
        return option

    def parseDeleteObjects(self, xml, headers=None):
        root = ET.fromstring(xml)
        deleted_list = []
        error_list = []
        deleteds = root.findall('Deleted')
        encoding_type = self._find_item(root, 'EncodingType')

        if deleteds:
            for d in deleteds:
                key = self._find_item(d, 'Key', encoding_type)
                versionId = self._find_item(d, 'VersionId')
                deleteMarker = d.find('DeleteMarker')
                deleteMarker = util.to_bool(deleteMarker.text) if deleteMarker is not None else None
                deleteMarkerVersionId = self._find_item(d, 'DeleteMarkerVersionId')
                deleted_list.append(DeleteObjectResult(key=key, deleteMarker=deleteMarker, versionId=versionId,
                                                       deleteMarkerVersionId=deleteMarkerVersionId))
        errors = root.findall('Error')
        if errors:
            for e in errors:
                _key = self._find_item(e, 'Key', encoding_type)
                _versionId = self._find_item(e, 'VersionId')
                _code = self._find_item(e, 'Code')
                _message = self._find_item(e, 'Message')
                error_list.append(ErrorResult(key=_key, versionId=_versionId, code=_code, message=_message))
        return DeleteObjectsResponse(deleted=deleted_list, error=error_list, encoding_type=encoding_type)

    def parseDeleteObject(self, headers):
        deleteObjectResponse = DeleteObjectResponse()
        delete_marker = headers.get(self.ha.delete_marker_header())
        deleteObjectResponse.deleteMarker = util.to_bool(delete_marker) if delete_marker is not None else None
        deleteObjectResponse.versionId = headers.get(self.ha.version_id_header())
        return deleteObjectResponse

    def parseGetBucketVersioning(self, xml, headers=None):
        root = ET.fromstring(xml)
        return self._find_item(root, 'Status')

    def parseGetBucketLifecycle(self, xml, headers=None):
        root = ET.fromstring(xml)
        rules = root.findall('Rule')
        entries = []
        for rule in rules:
            _id = self._find_item(rule, 'ID')
            prefix = self._find_item(rule, 'Prefix')
            status = self._find_item(rule, 'Status')
            expired = rule.find('Expiration')
            expiration = None
            if expired is not None:
                d = expired.find('Date')
                date = DateTime.UTCToLocalMid(d.text) if d is not None else None
                day = expired.find('Days')
                days = util.to_int(day.text) if day is not None else None
                expiration = Expiration(date=date, days=days)

            nocurrent_expire = rule.find('NoncurrentVersionExpiration')
            noncurrentVersionExpiration = NoncurrentVersionExpiration(noncurrentDays=util.to_int(
                nocurrent_expire.find('NoncurrentDays').text)) if nocurrent_expire is not None else None

            transis = rule.findall('Transition')

            transitions = self._parseGetBucketLifecycleTransis(transis)

            noncurrentVersionTransis = rule.findall('NoncurrentVersionTransition')
            noncurrentVersionTransitions = []
            if noncurrentVersionTransis is not None:
                for noncurrentVersionTransis in noncurrentVersionTransis:
                    storageClass = self._find_item(noncurrentVersionTransis, 'StorageClass')
                    noncurrentDays = noncurrentVersionTransis.find('NoncurrentDays')
                    noncurrentDays = util.to_int(noncurrentDays.text) if noncurrentDays is not None else None
                    noncurrentVersionTransition = NoncurrentVersionTransition(storageClass=storageClass,
                                                                              noncurrentDays=noncurrentDays)
                    noncurrentVersionTransitions.append(noncurrentVersionTransition)

            rule = Rule(id=_id, prefix=prefix, status=status, expiration=expiration,
                        noncurrentVersionExpiration=noncurrentVersionExpiration)
            rule.transition = transitions
            rule.noncurrentVersionTransition = noncurrentVersionTransitions
            entries.append(rule)
        return LifecycleResponse(lifecycleConfig=Lifecycle(rule=entries))

    def _parseGetBucketLifecycleTransis(self, transis):
        transitions = []
        if transis is not None:
            for transi in transis:
                d = transi.find('Date')
                date = DateTime.UTCToLocalMid(d.text) if d is not None else None
                days = transi.find('Days')
                days = util.to_int(days.text) if days is not None else None
                storageClass = self._find_item(transi, 'StorageClass')
                transition = Transition(storageClass, date=date, days=days)
                transitions.append(transition)
        return transitions

    def parseGetBucketWebsite(self, xml, headers=None):
        root = ET.fromstring(xml)
        redirectAll = None
        redirectAllRequestTo = root.find('RedirectAllRequestsTo')
        if redirectAllRequestTo is not None:
            hostname = self._find_item(redirectAllRequestTo, 'HostName')
            protocol = self._find_item(redirectAllRequestTo, 'Protocol')
            redirectAll = RedirectAllRequestTo(hostName=hostname, protocol=protocol)
            return WebsiteConfiguration(redirectAllRequestTo=redirectAll)

        index = None
        indexDocument = root.find('IndexDocument')
        if indexDocument is not None:
            Suffix = self._find_item(indexDocument, 'Suffix')
            index = IndexDocument(suffix=Suffix)

        error = None
        errorDocument = root.find('ErrorDocument')
        if errorDocument is not None:
            Key = self._find_item(errorDocument, 'Key')
            error = ErrorDocument(key=Key)

        routs = None
        routingRules = root.findall('RoutingRules/RoutingRule')
        if routingRules is not None and len(routingRules) > 0:
            routs = []
            for rout in routingRules:
                KeyPrefixEquals = rout.find('Condition/KeyPrefixEquals')
                KeyPrefixEquals = util.to_string(KeyPrefixEquals.text) if KeyPrefixEquals is not None else None
                HttpErrorCodeReturnedEquals = rout.find('Condition/HttpErrorCodeReturnedEquals')
                HttpErrorCodeReturnedEquals = util.to_int(
                    HttpErrorCodeReturnedEquals.text) if HttpErrorCodeReturnedEquals is not None else None

                condition = Condition(keyPrefixEquals=KeyPrefixEquals,
                                      httpErrorCodeReturnedEquals=HttpErrorCodeReturnedEquals)

                Protocol = self._find_item(rout, 'Redirect/Protocol')
                HostName = self._find_item(rout, 'Redirect/HostName')
                ReplaceKeyPrefixWith = self._find_item(rout, 'Redirect/ReplaceKeyPrefixWith')
                ReplaceKeyWith = self._find_item(rout, 'Redirect/ReplaceKeyWith')
                HttpRedirectCode = rout.find('Redirect/HttpRedirectCode')
                HttpRedirectCode = util.to_int(HttpRedirectCode.text) if HttpRedirectCode is not None else None
                redirect = Redirect(protocol=Protocol, hostName=HostName, replaceKeyPrefixWith=ReplaceKeyPrefixWith,
                                    replaceKeyWith=ReplaceKeyWith,
                                    httpRedirectCode=HttpRedirectCode)
                routingRule = RoutingRule(condition=condition, redirect=redirect)
                routs.append(routingRule)

        return WebsiteConfiguration(indexDocument=index, errorDocument=error, routingRules=routs)

    def parseGetBucketNotification(self, xml, headers=None):
        notification = Notification()
        root = ET.fromstring(xml)

        def _get_configuration(config_class, config_type, urn_type):
            topicConfigurations = root.findall(config_type)
            if topicConfigurations is not None:
                tc_list = []
                for topicConfiguration in topicConfigurations:
                    tc = config_class()
                    tc.id = self._find_item(topicConfiguration, 'Id')
                    setattr(tc, urn_type, self._find_item(topicConfiguration, urn_type))
                    event_list = []
                    events = topicConfiguration.findall('Event')
                    if events is not None:
                        for event in events:
                            event_list.append(util.to_string(event.text))

                    tc.events = event_list
                    filterRule_list = []
                    filterRules = topicConfiguration.findall(
                        'Filter/Object/FilterRule' if self.is_obs else 'Filter/S3Key/FilterRule')
                    if filterRules is not None:
                        for filterRule in filterRules:
                            name = filterRule.find('Name')
                            value = filterRule.find('Value')
                            fr = FilterRule(name=util.to_string(name.text) if name is not None else None,
                                            value=util.to_string(value.text)
                                            if value is not None else None)
                            filterRule_list.append(fr)
                    tc.filterRules = filterRule_list
                    tc_list.append(tc)
                return tc_list

        notification.topicConfigurations = _get_configuration(TopicConfiguration, 'TopicConfiguration', 'Topic')
        notification.functionGraphConfigurations = _get_configuration(FunctionGraphConfiguration,
                                                                      'FunctionGraphConfiguration', 'FunctionGraph')

        return notification

    def parseListMultipartUploads(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        bucket = self._find_item(root, 'Bucket')
        KeyMarker = self._find_item(root, 'KeyMarker', encoding_type)
        UploadIdMarker = self._find_item(root, 'UploadIdMarker')
        NextKeyMarker = self._find_item(root, 'NextKeyMarker', encoding_type)
        NextUploadIdMarker = self._find_item(root, 'NextUploadIdMarker')

        MaxUploads = root.find('MaxUploads')
        MaxUploads = util.to_int(MaxUploads.text) if MaxUploads is not None else None

        IsTruncated = root.find('IsTruncated')
        IsTruncated = util.to_bool(IsTruncated.text) if IsTruncated is not None else None

        prefix = self._find_item(root, 'Prefix', encoding_type)
        delimiter = self._find_item(root, 'Delimiter', encoding_type)

        rules = root.findall('Upload')
        uploadlist = []
        if rules:
            for rule in rules:
                Key = self._find_item(rule, 'Key', encoding_type)
                UploadId = self._find_item(rule, 'UploadId')

                ID = self._find_item(rule, 'Initiator/ID')

                DisplayName = None if self.is_obs else self._find_item(rule, 'Initiator/DisplayName')
                initiator = Initiator(id=ID, name=DisplayName)

                owner_id = self._find_item(rule, 'Owner/ID')
                owner_name = None if self.is_obs else self._find_item(rule, 'Owner/DisplayName')
                owner = Owner(owner_id=owner_id, owner_name=owner_name)

                StorageClass = self._find_item(rule, 'StorageClass')

                Initiated = rule.find('Initiated')
                Initiated = DateTime.UTCToLocal(Initiated.text) if Initiated is not None else None
                upload = Upload(key=Key, uploadId=UploadId, initiator=initiator, owner=owner, storageClass=StorageClass,
                                initiated=Initiated)
                uploadlist.append(upload)
        common = root.findall('CommonPrefixes')
        commonlist = []
        if common:
            for comm in common:
                comm_prefix = self._find_item(comm, 'Prefix', encoding_type)
                Comm_Prefix = CommonPrefix(prefix=comm_prefix)
                commonlist.append(Comm_Prefix)
        return ListMultipartUploadsResponse(bucket=bucket, keyMarker=KeyMarker, uploadIdMarker=UploadIdMarker,
                                            nextKeyMarker=NextKeyMarker, nextUploadIdMarker=NextUploadIdMarker,
                                            maxUploads=MaxUploads,
                                            isTruncated=IsTruncated, prefix=prefix, delimiter=delimiter,
                                            upload=uploadlist, commonPrefixs=commonlist, encoding_type=encoding_type)

    def parseCompleteMultipartUpload(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        location = self._find_item(root, 'Location')
        bucket = self._find_item(root, 'Bucket')
        key = self._find_item(root, 'Key', encoding_type)
        eTag = self._find_item(root, 'ETag')
        completeMultipartUploadResponse = CompleteMultipartUploadResponse(location=location, bucket=bucket, key=key,
                                                                          etag=eTag, encoding_type=encoding_type)
        completeMultipartUploadResponse.versionId = headers.get(self.ha.version_id_header())
        completeMultipartUploadResponse.sseKms = headers.get(self.ha.sse_kms_header())
        completeMultipartUploadResponse.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        completeMultipartUploadResponse.sseC = headers.get(self.ha.sse_c_header())
        completeMultipartUploadResponse.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())

        return completeMultipartUploadResponse

    def parseListParts(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        bucketName = self._find_item(root, 'Bucket')
        objectKey = self._find_item(root, 'Key', encoding_type)
        uploadId = self._find_item(root, 'UploadId')

        storageClass = self._find_item(root, 'StorageClass')
        partNumbermarker = root.find('PartNumberMarker')
        partNumbermarker = util.to_int(partNumbermarker.text) if partNumbermarker is not None else None
        nextPartNumberMarker = root.find('NextPartNumberMarker')
        nextPartNumberMarker = util.to_int(nextPartNumberMarker.text) if nextPartNumberMarker is not None else None
        maxParts = root.find('MaxParts')
        maxParts = util.to_int(maxParts) if maxParts is not None else None
        isTruncated = root.find('IsTruncated')
        isTruncated = util.to_bool(isTruncated.text) if isTruncated is not None else None

        initiatorid = self._find_item(root, 'Initiator/ID')
        displayname = None if self.is_obs else self._find_item(root, 'Initiator/DisplayName')

        initiator = Initiator(id=initiatorid, name=displayname)

        owner_id = self._find_item(root, 'Owner/ID')
        owner_name = self._find_item(root, 'Owner/DisplayName')
        owner = Owner(owner_id=owner_id, owner_name=owner_name)

        parts = self._parseListPartsHandleParts(root)

        return ListPartsResponse(bucketName=bucketName, objectKey=objectKey, uploadId=uploadId, initiator=initiator,
                                 owner=owner, storageClass=storageClass,
                                 partNumberMarker=partNumbermarker, nextPartNumberMarker=nextPartNumberMarker,
                                 maxParts=maxParts, isTruncated=isTruncated, parts=parts, encoding_type=encoding_type)

    def _parseListPartsHandleParts(self, root):
        part_list = root.findall('Part')
        parts = []
        if part_list:
            for part in part_list:
                part_number = part.find('PartNumber')
                part_number = util.to_int(part_number.text) if part_number is not None else None
                modified_date = part.find('LastModified')
                modified_date = DateTime.UTCToLocal(modified_date.text) if modified_date is not None else None
                etag = self._find_item(part, 'ETag')
                size = part.find('Size')
                size = util.to_long(size.text) if size is not None else None
                parts.append(Part(partNumber=part_number, lastModified=modified_date, etag=etag, size=size))
        return parts

    def parseGetBucketAcl(self, xml, headers=None):
        root = ET.fromstring(xml)
        owner_id = self._find_item(root, 'Owner/ID')
        owner_name = None if self.is_obs else self._find_item(root, 'Owner/DisplayName')
        owner = Owner(owner_id=owner_id, owner_name=owner_name)
        grants = root.findall('AccessControlList/Grant')
        return ACL(owner=owner, grants=self.parseGrants(grants))

    def parseGrants(self, grants, headers=None):
        grant_list = []
        if grants is not None:
            if self.is_obs:
                grant_list = self._parseGrantsIsObs(grants, grant_list)
            else:
                ns = '{http://www.w3.org/2001/XMLSchema-instance}'
                grantee = None
                for grant in grants:
                    if grant.find('Grantee').attrib.get('{0}type'.format(ns)) == 'Group':
                        group1 = self._find_item(grant, 'Grantee/URI')
                        grantee = Grantee(group=group1)
                    elif grant.find('Grantee').attrib.get('{0}type'.format(ns)) == 'CanonicalUser':
                        owner_id = self._find_item(grant, 'Grantee/ID')
                        owner_name = None if self.is_obs else self._find_item(grant, 'Grantee/DisplayName')
                        grantee = Grantee(grantee_id=owner_id, grantee_name=owner_name)

                    permission = self._find_item(grant, 'Permission')
                    cur_grant = Grant(grantee=grantee, permission=permission)
                    grant_list.append(cur_grant)
        return grant_list

    def _parseGrantsIsObs(self, grants, grant_list):
        for grant in grants:
            group1 = grant.find('Grantee/Canned')
            if group1 is not None:
                grantee = Grantee(group=util.to_string(group1.text))
            else:
                _id = grant.find('Grantee/ID')
                grantee = Grantee(grantee_id=_id.text if _id is not None else None)
            permission = self._find_item(grant, 'Permission')
            delivered = grant.find('Delivered')
            delivered = util.to_string(delivered.text) if delivered is not None else None
            cur_grant = Grant(grantee=grantee, permission=permission,
                              delivered=delivered == 'true')
            grant_list.append(cur_grant)
        return grant_list

    def parseGetBucketLogging(self, xml, headers=None):
        root = ET.fromstring(xml)
        bucket = self._find_item(root, 'LoggingEnabled/TargetBucket')
        prefix = self._find_item(root, 'LoggingEnabled/TargetPrefix')
        agency = self._find_item(root, 'Agency')
        grants = root.findall('LoggingEnabled/TargetGrants/Grant')
        return Logging(targetBucket=bucket, targetPrefix=prefix, targetGrants=self.parseGrants(grants), agency=agency)

    def parseGetObjectAcl(self, xml, headers=None):
        root = ET.fromstring(xml)
        owner_id = self._find_item(root, 'Owner/ID')
        owner_name = None
        if not self.is_obs:
            owner_name = self._find_item(root, 'Owner/DisplayName')
            delivered = None
        else:
            delivered = self._find_item(root, 'Delivered')

        owner = Owner(owner_id=owner_id, owner_name=owner_name)
        grants = root.findall('AccessControlList/Grant')
        return ACL(owner=owner, grants=self.parseGrants(grants), delivered=True if delivered == 'true' else False)

    def parsePutContent(self, headers):
        option = PutContentResponse()
        option.storageClass = headers.get(self.ha.storage_class_header())
        option.versionId = headers.get(self.ha.version_id_header())
        option.sseKms = headers.get(self.ha.sse_kms_header())
        option.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        option.sseC = headers.get(self.ha.sse_c_header())
        option.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        option.etag = headers.get(const.ETAG_HEADER.lower())
        return option

    def parseAppendObject(self, headers):
        option = AppendObjectResponse()
        option.storageClass = headers.get(self.ha.storage_class_header())
        option.sseKms = headers.get(self.ha.sse_kms_header())
        option.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        option.sseC = headers.get(self.ha.sse_c_header())
        option.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        option.etag = headers.get(const.ETAG_HEADER.lower())
        option.nextPosition = util.to_long(headers.get(self.ha.next_position_header()))
        return option

    def parseInitiateMultipartUpload(self, xml, headers=None):
        root = ET.fromstring(xml)
        encoding_type = self._find_item(root, 'EncodingType')

        bucketName = self._find_item(root, 'Bucket')
        objectKey = self._find_item(root, 'Key', encoding_type)
        uploadId = self._find_item(root, 'UploadId')
        response = InitiateMultipartUploadResponse(bucketName=bucketName, objectKey=objectKey, uploadId=uploadId,
                                                   encoding_type=encoding_type)
        response.sseKms = headers.get(self.ha.sse_kms_header())
        response.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        response.sseC = headers.get(self.ha.sse_c_header())
        response.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        return response

    def parseCopyObject(self, xml, headers=None):
        root = ET.fromstring(xml)
        lastModified = root.find('LastModified')
        lastModified = DateTime.UTCToLocal(lastModified.text) if lastModified is not None else None
        eTag = self._find_item(root, 'ETag')
        copyObjectResponse = CopyObjectResponse(lastModified=lastModified, etag=eTag)
        copyObjectResponse.versionId = headers.get(self.ha.version_id_header())
        copyObjectResponse.copySourceVersionId = headers.get(self.ha.copy_source_version_id())
        copyObjectResponse.sseKms = headers.get(self.ha.sse_kms_header())
        copyObjectResponse.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        copyObjectResponse.sseC = headers.get(self.ha.sse_c_header())
        copyObjectResponse.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        return copyObjectResponse

    def _parseGetObjectCommonHeader(self, headers, option):
        option.accessContorlAllowOrigin = headers.get('access-control-allow-origin')
        option.accessContorlAllowHeaders = headers.get('access-control-allow-headers')
        option.accessContorlAllowMethods = headers.get('access-control-allow-methods')
        option.accessContorlExposeHeaders = headers.get('access-control-expose-headers')
        option.accessContorlMaxAge = util.to_int(headers.get('access-control-max-age'))
        option.storageClass = headers.get(self.ha.storage_class_header())
        option.expiration = headers.get(self.ha.expiration_header())
        option.versionId = headers.get(self.ha.version_id_header())
        option.websiteRedirectLocation = headers.get(self.ha.website_redirect_location_header())
        option.sseKms = headers.get(self.ha.sse_kms_header())
        option.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        option.sseC = headers.get(self.ha.sse_c_header())
        option.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        option.restore = headers.get(self.ha.restore_header())
        option.etag = headers.get(const.ETAG_HEADER.lower())
        option.contentLength = util.to_long(headers.get(const.CONTENT_LENGTH_HEADER.lower()))
        option.contentType = headers.get(const.CONTENT_TYPE_HEADER.lower())
        option.lastModified = headers.get(const.LAST_MODIFIED_HEADER.lower())

    def parseGetObjectMetadata(self, headers):
        option = GetObjectMetadataResponse()
        self._parseGetObjectCommonHeader(headers, option)
        option.isAppendable = headers.get(self.ha.object_type_header()) == 'Appendable'
        if option.isAppendable:
            option.nextPosition = util.to_long(headers.get(self.ha.next_position_header()))
        return option

    def parseSetObjectMetadata(self, headers):
        option = SetObjectMetadataResponse()
        self._parseGetObjectCommonHeader(headers, option)
        option.isAppendable = headers.get(self.ha.object_type_header()) == 'Appendable'
        if option.isAppendable:
            option.nextPosition = util.to_long(headers.get(self.ha.next_position_header()))
        return option

    def parseGetObject(self, headers, option):
        self._parseGetObjectCommonHeader(headers, option)
        option.deleteMarker = headers.get(self.ha.delete_marker_header())
        option.cacheControl = headers.get(const.CACHE_CONTROL_HEADER.lower())
        option.contentDisposition = headers.get(const.CONTENT_DISPOSITION_HEADER.lower())
        option.contentEncoding = headers.get(const.CONTENT_ENCODING_HEADER.lower())
        option.contentLanguage = headers.get(const.CONTENT_LANGUAGE_HEADER.lower())
        option.expires = headers.get(const.EXPIRES_HEADER.lower())
        return option

    def parseUploadPart(self, headers):
        uploadPartResponse = UploadPartResponse()
        uploadPartResponse.etag = headers.get(const.ETAG_HEADER.lower())
        uploadPartResponse.sseKms = headers.get(self.ha.sse_kms_header())
        uploadPartResponse.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        uploadPartResponse.sseC = headers.get(self.ha.sse_c_header())
        uploadPartResponse.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        return uploadPartResponse

    def parseCopyPart(self, xml, headers=None):
        root = ET.fromstring(xml)
        lastModified = root.find('LastModified')
        lastModified = DateTime.UTCToLocal(lastModified.text) if lastModified is not None else None
        etag = self._find_item(root, 'ETag')
        copyPartResponse = CopyPartResponse(modifiedDate=lastModified, lastModified=lastModified, etag=etag)
        copyPartResponse.sseKms = headers.get(self.ha.sse_kms_header())
        copyPartResponse.sseKmsKey = headers.get(self.ha.sse_kms_key_header())
        copyPartResponse.sseC = headers.get(self.ha.sse_c_header())
        copyPartResponse.sseCKeyMd5 = headers.get(self.ha.sse_c_key_md5_header().lower())
        return copyPartResponse

    def parseGetBucketReplication(self, xml, headers=None):
        root = ET.fromstring(xml)
        agency = None
        if self.is_obs:
            agency = self._find_item(root, 'Agency')
        _rules = []
        rules = root.findall('Rule')
        if rules is not None:
            for rule in rules:
                _id = self._find_item(rule, 'ID')
                prefix = self._find_item(rule, 'Prefix')
                status = self._find_item(rule, 'Status')
                bucket = self._find_item(rule, 'Destination/Bucket')
                storageClass = self._find_item(rule, 'Destination/StorageClass')
                deleteData = self._find_item(rule, 'Destination/DeleteData')
                historicalObjectReplication = self._find_item(rule, 'Destination/HistoricalObjectReplication')
                _rules.append(
                    ReplicationRule(id=_id, prefix=prefix, status=status, bucket=bucket, storageClass=storageClass,
                                    deleteData=deleteData, historicalObjectReplication=historicalObjectReplication))
        replication = Replication(agency=agency, replicationRules=_rules)
        return replication

    def parseGetBucketRequestPayment(self, xml, headers=None):
        root = ET.fromstring(xml)
        payer = self._find_item(root, 'Payer')
        payment = GetBucketRequestPaymentResponse(payer=payer)
        return payment

    @staticmethod
    def _find_json_item(value, item_name):
        result = value.get(item_name)
        if result is None:
            return None
        if const.IS_PYTHON2:
            result = util.safe_encode(result)
        return util.to_string(result)

    def parseJsonErrorResult(self, jsons):
        result = json.loads(jsons)
        code = self._find_json_item(result, "code")
        message = self._find_json_item(result, "message")
        requestId = self._find_json_item(result, "request_id")
        return code, message, requestId

    # OEF parse func
    def parseGetBucketFetchPolicy(self, jsons, headers=None):
        result = json.loads(jsons)
        status = None
        agency = None
        fetchResult = result.get("fetch")
        if fetchResult is not None:
            status = self._find_json_item(fetchResult, "status")
            agency = self._find_json_item(fetchResult, "agency")
        policy = FetchPolicy(status=status, agency=agency)
        return policy

    def parseSetBucketFetchJob(self, jsons, headers=None):
        result = json.loads(jsons)
        ID = self._find_json_item(result, "id")
        wait = result.get("Wait")
        response = SetBucketFetchJobResponse(id=ID, wait=wait)
        return response

    def parseGetBucketFetchJob(self, jsons, header=None):
        result = json.loads(jsons)
        err = self._find_json_item(result, "err")
        code = self._find_json_item(result, "code")
        status = self._find_json_item(result, "status")

        job = result.get("job")
        if job is None:
            response = GetBucketFetchJobResponse(code=code, status=status, job=None, err=err)
            return response

        url = self._find_json_item(job, "url")
        host = self._find_json_item(job, "host")
        bucket = self._find_json_item(job, "bucket")
        key = self._find_json_item(job, "key")
        md5 = self._find_json_item(job, "md5")
        fileType = self._find_json_item(job, "file_type")
        ignoreSameKey = job.get('ignore_same_key')
        callBackUrl = self._find_json_item(job, "callbackurl")
        callBackBody = self._find_json_item(job, "callbackbody")
        callBackHost = self._find_json_item(job, "callbackhost")
        callBackBodyType = self._find_json_item(job, "callbackbodytype")
        fetchJobResponse = FetchJobResponse(url=url, host=host, bucket=bucket, key=key, md5=md5, fileType=fileType,
                                            ignoreSameKey=ignoreSameKey, callBackUrl=callBackUrl,
                                            callBackBody=callBackBody,
                                            callBackHost=callBackHost, callBackBodyType=callBackBodyType)

        response = GetBucketFetchJobResponse(code=code, status=status, job=fetchJobResponse, err=err)
        return response

    # begin workflow related
    # begin workflow related
    # begin workflow related

    @staticmethod
    def parseGetJsonResponse(jsons, header=None):
        return jsons

    @staticmethod
    def parseCreateWorkflowTemplateResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        templateName = result.get('template_name')
        return CreateWorkflowTemplateResponse(templateName=templateName)

    @staticmethod
    def parseGetWorkflowTemplateResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        templateName = result.get('template_name')
        description = result.get('description')
        states = result.get('states')
        inputs = result.get('inputs')
        tags = result.get('tags')
        createTime = result.get('create_time')
        lastModifyTime = result.get('last_modify_time')
        return GetWorkflowTemplateResponse(templateName=templateName, description=description, states=states,
                                           inputs=inputs, tags=tags, createTime=createTime,
                                           lastModifyTime=lastModifyTime)

    @staticmethod
    def parseListWorkflowTemplateResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        count = result.get('count')
        templates = result.get('templates')
        nextStart = result.get('next_start')
        isTruncated = result.get('is_truncated')
        return ListWorkflowTemplateResponse(templates=templates, count=count, nextStart=nextStart,
                                            isTruncated=isTruncated)

    @staticmethod
    def parseCreateWorkflowResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        graphName = result.get('graph_name')
        graphUrn = result.get('graph_urn')
        createdAt = result.get('created_at')
        return CreateWorkflowResponse(graphName=graphName, graphUrn=graphUrn, createdAt=createdAt)

    @staticmethod
    def parseGetWorkflowResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        name = result.get('name')
        createdAt = result.get('created_at')
        definition = result.get('definition')
        graphUrn = result.get('graph_urn')
        description = result.get('description')
        return GetWorkflowResponse(name=name, createdAt=createdAt, definition=definition, graphUrn=graphUrn,
                                   description=description)

    @staticmethod
    def parseUpdateWorkflowResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        graphName = result.get('graph_name')
        graphUrn = result.get('graph_urn')
        lastModified = result.get('last_modified')
        return UpdateWorkflowResponse(graphName=graphName, graphUrn=graphUrn, lastModified=lastModified)

    @staticmethod
    def parseListWorkflowResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        count = result.get('count')
        graphs = result.get('graphs')
        nextStart = result.get('next_start')
        isTruncated = result.get('is_truncated')
        return ListWorkflowResponse(graphs=graphs, count=count, nextStart=nextStart, isTruncated=isTruncated)

    @staticmethod
    def parseAsyncAPIStartWorkflowResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        executionUrn = result.get('execution_urn')
        startedAt = result.get('started_at')
        executionName = result.get('execution_name')
        return AsyncAPIStartWorkflowResponse(executionUrn=executionUrn, startedAt=startedAt,
                                             executionName=executionName)

    @staticmethod
    def parseListWorkflowExecutionResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        count = result.get('count')
        nextMarker = result.get('next_marker')
        isTruncated = result.get('is_truncated')
        executions = result.get('executions')
        return ListWorkflowExecutionResponse(count=count, nextMarker=nextMarker, isTruncated=isTruncated,
                                             executions=executions)

    @staticmethod
    def parseGetWorkflowExecutionResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        executionInfo = result.get('execution_info')
        return GetWorkflowExecutionResponse(executionInfo=executionInfo)

    @staticmethod
    def parseRestoreFailedWorkflowExecutionResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        executionUrn = result.get('execution_urn')
        restoredAt = result.get('restored_at')
        executionName = result.get('execution_name')
        return RestoreFailedWorkflowExecutionResponse(executionUrn=executionUrn, restoredAt=restoredAt,
                                                      executionName=executionName)

    @staticmethod
    def parseGetTriggerPolicyResponse(jsons, header=None):
        result = util.jsonLoadsForPy2(jsons) if const.IS_PYTHON2 else json.loads(jsons)
        rules = result.get('rules')
        return GetTriggerPolicyResponse(rules=rules)

    # end workflow related
    # end workflow related
    # end workflow related

    # begin virtual bucket related
    # begin virtual bucket related
    # begin virtual bucket related

    def trans_set_bucket_alias(self, **kwargs):
        aliasInfo = kwargs.get('aliasInfo')
        entity = None if aliasInfo is None or len(aliasInfo) == 0 else self.trans_set_aliasInfo(aliasInfo)
        return {'pathArgs': {const.OBSBUCKETALIAS_PARAM: None}, 'entity': entity}

    def trans_set_aliasInfo(self, aliasInfo):
        root = ET.Element('CreateBucketAlias')
        bucketListEle = ET.SubElement(root, 'BucketList')
        ET.SubElement(bucketListEle, 'Bucket').text = util.to_string(aliasInfo.get('bucket1'))
        ET.SubElement(bucketListEle, 'Bucket').text = util.to_string(aliasInfo.get('bucket2'))
        return ET.tostring(root, 'UTF-8')

    def trans_bind_bucket_alias(self, **kwargs):
        aliasInfo = kwargs.get('aliasInfo')
        entity = None if aliasInfo is None or len(aliasInfo) == 0 else self.trans_bind_aliasInfo(aliasInfo)
        return {'pathArgs': {const.OBSALIAS_PARAM: None}, 'entity': entity}

    def trans_bind_aliasInfo(self, aliasInfo):
        root = ET.Element('AliasList')
        ET.SubElement(root, 'Alias').text = util.to_string(aliasInfo.get('alias'))
        return ET.tostring(root, 'UTF-8')

    def parseGetBucketAlias(self, xml, header=None):
        root = ET.fromstring(xml)
        bucketAliasXml = root.find('BucketAlias')
        alias = self._find_item(bucketAliasXml, 'Alias')
        bucketAlias = BucketAliasModel(alias=alias)

        bucketListXml = bucketAliasXml.find('BucketList').findall('Bucket')
        bucketNameList = []
        for bucketXml in bucketListXml:
            bucketNameList.append(self._find_text(bucketXml.text))

        if len(bucketNameList) > 0:
            bucketAlias.bucket1 = bucketNameList[0]
        if len(bucketNameList) > 1:
            bucketAlias.bucket2 = bucketNameList[1]

        return bucketAlias

    def parseListBucketAlias(self, xml, header=None):
        root = ET.fromstring(xml)
        ownerXml = root.find('Owner')
        ownerID = self._find_item(ownerXml, 'ID')
        listBucketAlias = ListBucketAliasModel(owner=ownerID)

        bucketAliasListXml = root.find('BucketAliasList').findall('BucketAlias')
        bucketAliasList = []
        for bucketAliasXml in bucketAliasListXml:
            alias = self._find_item(bucketAliasXml, 'Alias')
            creationDate = self._find_item(bucketAliasXml, 'CreationDate')
            bucketAlias = BucketAliasModel(alias=alias, creationDate=creationDate)

            bucketListXml = bucketAliasXml.find('BucketList').findall('Bucket')
            bucketNameList = []
            for bucketXml in bucketListXml:
                bucketNameList.append(self._find_text(bucketXml.text))

            if len(bucketNameList) > 0:
                bucketAlias.bucket1 = bucketNameList[0]
            if len(bucketNameList) > 1:
                bucketAlias.bucket2 = bucketNameList[1]

            bucketAliasList.append(bucketAlias)

        listBucketAlias.bucketAlias = bucketAliasList
        return listBucketAlias

    # end virtual bucket related
    # end virtual bucket related
    # end virtual bucket related
