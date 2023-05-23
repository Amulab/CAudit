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

import time
import threading
from modules.huaweiapi.obs import const

if const.IS_PYTHON2:
    import Queue as queue
else:
    import queue


class ProgressNotifier(object):

    def __init__(self, callback=None, totalAmount=0, interval=102400):
        self.callback = callback
        if self.callback is None or not callable(self.callback):
            raise Exception('Invalid callback')
        self.totalAmount = totalAmount
        self.interval = interval
        self._transferredAmount = const.LONG(0)
        self._newlyTransferredAmount = const.LONG(0)
        self._queue = queue.Queue()
        self._startCheckpoint = None

    def _run(self):
        while True:
            data = self._queue.get()
            if data is None:
                self._queue = None
                break
            self._transferredAmount += data
            self._newlyTransferredAmount += data
            if self._newlyTransferredAmount >= self.interval and (
                    self._transferredAmount < self.totalAmount or self.totalAmount <= 0):
                self._newlyTransferredAmount = 0
                self.callback(*self._calculate())

    def start(self):
        now = time.time()
        self._startCheckpoint = now
        t = threading.Thread(target=(self._run))
        t.daemon = True
        t.start()

    def _calculate(self):
        totalSeconds = time.time() - self._startCheckpoint
        return self._transferredAmount, self.totalAmount, totalSeconds if totalSeconds > 0 else 0.001

    def send(self, data):
        if isinstance(data, (const.LONG, int)):
            self._queue.put(data)

    def end(self):
        self._queue.put(None)
        self.callback(*self._calculate())
        self.callback = None


class NoneNotifier(object):
    def send(self, data):
        pass

    def start(self):
        pass

    def end(self):
        pass


NONE_NOTIFIER = NoneNotifier()
