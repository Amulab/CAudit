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

from modules.huaweiapi.obs.loadtoken import NoneTokenException


def get_token(security_providers, name='OBS_DEFAULT'):
    if name == 'OBS_DEFAULT':
        for method in security_providers:
            try:
                value = method.search()
            except Exception:
                pass
            else:
                return {'accessKey': value.get('accessKey'),
                        'secretKey': value.get('secretKey'),
                        'securityToken': value.get('securityToken')}
        raise NoneTokenException('get token failed')

    for method in security_providers:
        if getattr(method, '__name__') == name:
            try:
                value = method.search()
            except Exception:
                raise
            else:
                return {'accessKey': value.get('accessKey'),
                        'secretKey': value.get('secretKey'),
                        'securityToken': value.get('securityToken')}
    raise ValueError('No such method: ' + name)
