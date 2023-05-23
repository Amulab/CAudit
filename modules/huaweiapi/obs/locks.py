#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2019 Huawei Technologies Co.,Ltd.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.  You may obtain a copy of the
# License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.

import threading

LOCK_COUNT = 16
lock_list = []

for i in range(LOCK_COUNT):
    lock_list.append(threading.RLock())


def get_lock(index):
    if index < 0 or index >= LOCK_COUNT:
        raise Exception('cannot find a valid lock')

    return lock_list[index]
