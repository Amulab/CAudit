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


from __future__ import absolute_import
import traceback
import threading
import functools
import json
import time
from modules.huaweiapi.obs import const
from modules.huaweiapi.obs.client import _BasicClient
from modules.huaweiapi.obs.ilog import INFO
from modules.huaweiapi.obs.util import jsonLoadsForPy2


def combine(*args):
    return '/'.join(args)


def prepareHeader():
    return {const.CONTENT_TYPE_HEADER: const.MIME_TYPES.get('json')}


def prepareJson(kwargs, pop=None):
    kwargs.pop('self')
    if bool(kwargs):
        if bool(pop):
            for p in list(pop):
                kwargs.pop(p)
        if not bool(kwargs):
            return None
        return json.dumps(kwargs, ensure_ascii=False)
    else:
        return None


def _resultFilter(result, executionState):
    for e in result[::-1]:
        if e.get('execution_state') != executionState:
            result.remove(e)
    return result


def _listWorkflowExecutionMethodName(isJsonResult, defaultMethodName):
    return 'ListWorkflowExecutionResponse' if not isJsonResult else defaultMethodName


def _listWorkflowExecutionCount(isJsonResult, body):
    return body.count if not isJsonResult else body.get('count')


def _listWorkflowExecutionBody(isJsonResult, isPy2, body):
    if isJsonResult:
        body = jsonLoadsForPy2(body) if isPy2 else json.loads(body)
    return body


def _listWorkflowExecutionResult(isJsonResult, body):
    return list(body.executions) if not isJsonResult else list(body.get('executions'))


def _listWorkflowExecutionIsTruncated(isJsonResult, body):
    return body.isTruncated if not isJsonResult else body.get('is_truncated')


def _listWorkflowExecutionNextMarker(isTruncated, isJsonResult, body):
    if isTruncated:
        nextMarker = body.nextMarker if not isJsonResult else body.get('next_marker')
    else:
        nextMarker = None
    return nextMarker


def _listWorkflowExecutionPathArgs(graphName, nextMarker, limit, executionType):
    pathArgs = {'x-workflow-graph-name': graphName}
    if nextMarker:
        pathArgs['x-workflow-next-marker'] = nextMarker
    if limit:
        if limit > 1000:
            raise Exception('Invalid parameter: limit')
        pathArgs['x-workflow-limit'] = limit
    if executionType:
        pathArgs['x-workflow-execution-type'] = executionType
    return pathArgs


def _listWorkflowExecutionResp(isJsonResult, resp, result, isTruncated, nextMarker):
    if isJsonResult:
        resp.body = {
            'count': len(result),
            'is_truncated': isTruncated,
            'executions': result
        }
        if isTruncated:
            resp.body['next_marker'] = nextMarker
        else:
            if resp.body.get('next_marker') is not None:
                del resp.body['next_marker']
        resp.body = json.dumps(resp.body)
    else:
        resp.body.count = len(result)
        resp.body.executions = result
        resp.body.isTruncated = isTruncated
        if isTruncated:
            resp.body.nextMarker = nextMarker
        else:
            if resp.body.nextMarker is not None:
                del resp.body.nextMarker

    return resp


def entrance(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        workflowClient = args[0] if isinstance(args[0], WorkflowClient) else None
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if workflowClient:
                workflowClient.log_client.log(INFO, traceback.format_exc())
            raise e
        finally:
            if workflowClient:
                workflowClient.log_client.log(INFO,
                                              '%s cost %s ms' % (func.__name__, int((time.time() - start) * 1000)))

    return wrapper


class WorkflowClient(_BasicClient):
    _instance_lock = threading.Lock()
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self, isJsonResult=False, *args, **kwargs):
        if kwargs.get('path_style') or kwargs.get('is_signature_negotiation'):
            raise Exception('Path style or signature negotiation does not support custom settings for workflow client.')
        super(WorkflowClient, self).__init__(client_mode='workflow', *args, **kwargs)
        self.__resource = 'v2/'
        self.__isJsonResult = isJsonResult
        self.__defaultMethodName = 'GetJsonResponse'

    # begin workflow api
    # begin workflow api
    # begin workflow api

    @entrance
    def createWorkflowTemplate(self, templateName, description=None, states=None, inputs=None, tags=None):
        return self._make_post_request(
            entity=prepareJson(locals(), ['templateName']),
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_TEMPLATES, templateName),
            headers=prepareHeader(),
            methodName='CreateWorkflowTemplateResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def getWorkflowTemplate(self, templateName):
        return self._make_get_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_TEMPLATES, templateName),
            headers=prepareHeader(),
            methodName='GetWorkflowTemplateResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def deleteWorkflowTemplate(self, templateName):
        return self._make_delete_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_TEMPLATES, templateName),
            headers=prepareHeader(),
            methodName=self.__defaultMethodName
        )

    @entrance
    def listWorkflowTemplate(self, templateNamePrefix=None, start=None, limit=None):
        pathArgs = {'x-workflow-prefix': None}
        if start:
            pathArgs['x-workflow-start'] = start
        if limit:
            pathArgs['x-workflow-limit'] = limit

        return self._make_get_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_TEMPLATES,
                                                templateNamePrefix if templateNamePrefix is not None else ''),
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName='ListWorkflowTemplateResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def createWorkflow(self, templateName, graphName, agency, description=None, parameters=None):
        return self._make_post_request(
            entity=prepareJson(locals(), ['templateName', 'graphName']),
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS, graphName),
            pathArgs={'x-workflow-template-name': templateName},
            headers=prepareHeader(),
            methodName='CreateWorkflowResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def getWorkflow(self, graphName):
        return self._make_get_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS, graphName),
            headers=prepareHeader(),
            methodName='GetWorkflowResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def deleteWorkflow(self, graphName):
        return self._make_delete_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS, graphName),
            headers=prepareHeader(),
            methodName=self.__defaultMethodName
        )

    @entrance
    def updateWorkflow(self, graphName, parameters=None, description=None):
        return self._make_put_request(
            entity=prepareJson(locals(), ['graphName']),
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS, graphName),
            headers=prepareHeader(),
            methodName='UpdateWorkflowResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def listWorkflow(self, graphNamePrefix=None, start=None, limit=None):
        pathArgs = {'x-workflow-prefix': None}
        if start:
            pathArgs['x-workflow-start'] = start
        if limit:
            pathArgs['x-workflow-limit'] = limit

        return self._make_get_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS,
                                                graphNamePrefix if graphNamePrefix is not None else ''),
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName='ListWorkflowResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def asyncAPIStartWorkflow(self, graphName, bucket, object, inputs=None):
        return self._make_post_request(
            entity=prepareJson(locals(), ['graphName']),
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOWS, graphName),
            headers=prepareHeader(),
            methodName='AsyncAPIStartWorkflowResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def listWorkflowExecution(self, graphName, executionType=None, nextMarker=None, limit=None, executionState=None):
        pathArgs = _listWorkflowExecutionPathArgs(graphName, nextMarker, limit, executionType)
        if executionState:
            if executionState not in ['RUNNING', 'SUCCESS', 'FAILED']:
                raise Exception('Invalid parameter: execution state')

            resp = self._make_get_request(
                bucketName=None,
                objectKey=self.__resource + const.WORKFLOW_EXECUTIONS,
                pathArgs=pathArgs,
                headers=prepareHeader(),
                methodName=_listWorkflowExecutionMethodName(self.__isJsonResult, self.__defaultMethodName)
            )
            if resp.status > 300:
                return resp

            body = _listWorkflowExecutionBody(self.__isJsonResult, const.IS_PYTHON2, resp.body)

            count = _listWorkflowExecutionCount(self.__isJsonResult, body)

            if count == 0:
                return resp

            result = _listWorkflowExecutionResult(self.__isJsonResult, body)
            isTruncated = _listWorkflowExecutionIsTruncated(self.__isJsonResult, body)
            nextMarker = _listWorkflowExecutionNextMarker(isTruncated, self.__isJsonResult, body)

            result = _resultFilter(result, executionState)

            if len(result) == limit:
                return resp
            else:
                while len(result) < limit and isTruncated:
                    pathArgs['x-workflow-next-marker'] = nextMarker
                    tempResp = self._make_get_request(
                        bucketName=None,
                        objectKey=self.__resource + const.WORKFLOW_EXECUTIONS,
                        pathArgs=pathArgs,
                        headers=prepareHeader(),
                        methodName=_listWorkflowExecutionMethodName(self.__isJsonResult, self.__defaultMethodName)
                    )
                    if tempResp.status > 300:
                        return tempResp

                    body = _listWorkflowExecutionBody(self.__isJsonResult, const.IS_PYTHON2, tempResp.body)

                    count = _listWorkflowExecutionCount(self.__isJsonResult, body)
                    if count == 0:
                        return tempResp

                    tempResult = _listWorkflowExecutionResult(self.__isJsonResult, body)

                    tempResult = _resultFilter(tempResult, executionState)

                    result.extend(tempResult)

                    if len(result) > limit:
                        result = result[0:limit]

                    isTruncated = _listWorkflowExecutionIsTruncated(self.__isJsonResult, body)
                    nextMarker = _listWorkflowExecutionNextMarker(isTruncated, self.__isJsonResult, body)

            return _listWorkflowExecutionResp(self.__isJsonResult, resp, result, isTruncated, nextMarker)
        else:
            return self._make_get_request(
                bucketName=None,
                objectKey=self.__resource + const.WORKFLOW_EXECUTIONS,
                pathArgs=pathArgs,
                headers=prepareHeader(),
                methodName=_listWorkflowExecutionMethodName(self.__isJsonResult, self.__defaultMethodName)
            )

    @entrance
    def getWorkflowExecution(self, executionName, graphName):
        pathArgs = {
            'x-workflow-graph-name': graphName
        }

        return self._make_get_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_EXECUTIONS, executionName),
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName='GetWorkflowExecutionResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def restoreFailedWorkflowExecution(self, executionName, graphName):
        pathArgs = {
            'x-workflow-graph-name': graphName
        }

        return self._make_put_request(
            bucketName=None,
            objectKey=self.__resource + combine(const.WORKFLOW_EXECUTIONS, executionName),
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName='RestoreFailedWorkflowExecutionResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def putTriggerPolicy(self, bucketName, rules):
        pathArgs = {
            const.WORKFLOW_TRIGGERPOLICY: None
        }

        return self._make_put_request(
            entity=prepareJson(locals(), ['bucketName']),
            bucketName=bucketName,
            objectKey=None,
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName=self.__defaultMethodName
        )

    @entrance
    def getTriggerPolicy(self, bucketName):
        pathArgs = {
            const.WORKFLOW_TRIGGERPOLICY: None
        }

        return self._make_get_request(
            bucketName=bucketName,
            objectKey=None,
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName='GetTriggerPolicyResponse' if not self.__isJsonResult else self.__defaultMethodName
        )

    @entrance
    def deleteTriggerPolicy(self, bucketName):
        pathArgs = {
            const.WORKFLOW_TRIGGERPOLICY: None
        }

        return self._make_delete_request(
            bucketName=bucketName,
            objectKey=None,
            pathArgs=pathArgs,
            headers=prepareHeader(),
            methodName=self.__defaultMethodName
        )

    # end workflow api
    # end workflow api
    # end workflow api
