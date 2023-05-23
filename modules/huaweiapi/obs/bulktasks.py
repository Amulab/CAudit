#!/usr/bin/env python
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

import threading
from modules.huaweiapi.obs import const
from modules.huaweiapi.obs import util

if const.IS_PYTHON2:
    import Queue as queue
else:
    import queue


class ThreadPool(object):

    def __init__(self, thread_size=const.DEFAULT_TASK_NUM, queue_size=const.DEFAULT_TASK_QUEUE_SIZE):
        self.thread_size = thread_size
        self._alive_threads = 0
        self._task_queue = queue.Queue(queue_size)
        self._threads = []
        self._init_threads()
        self._shutdown_lock = threading.Lock()

    def _init_threads(self):
        for i in range(self.thread_size):
            self._alive_threads += 1
            work_thread = threading.Thread(target=self._run)
            self._threads.append(work_thread)
            work_thread.start()

    def _run(self):
        task = self._task_queue.get()
        while task is not None:
            (func, args, kwargs, future) = task

            if future is None:
                result = func(*args, **kwargs)
            else:
                try:
                    result = func(*args, **kwargs)
                except Exception as e:
                    future.set_exception(e)
                else:
                    future.set_result(result)

            del task

            task = self._task_queue.get()

    def execute(self, func, *args, **kwargs):
        task = (func, args, kwargs, None)
        self._task_queue.put(task)

    def submit(self, func, *args, **kwargs):
        future = Future()
        task = (func, args, kwargs, future)
        self._task_queue.put(task)
        return future

    def shutdown(self, wait=True):
        with self._shutdown_lock:
            while self._alive_threads:
                self._task_queue.put(None)
                self._alive_threads -= 1
            if wait:
                for t in self._threads:
                    t.join()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown(wait=True)
        return False


class TimeoutError(Exception):
    pass


PENDING = 'PENDING'
COMPLETED = 'COMPLETED'


class Future(object):
    def __init__(self):
        self._condition = threading.Condition()
        self._state = PENDING
        self._result = None
        self._exception = None
        self._callback = None

    def set_result(self, result):
        with self._condition:
            self._result = result
            self._state = COMPLETED
            self._condition.notify_all()

        if self._callback:
            self._callback(self)

    def set_exception(self, exception):
        with self._condition:
            self._exception = exception
            self._state = COMPLETED
            self._condition.notify_all()

        if self._callback:
            self._callback(self)

    def set_callback(self, callback):
        with self._condition:
            if self._state is PENDING:
                self._callback = callback
                return
        callback(self)

    def _get_result(self):
        if self._exception:
            raise self._exception  # pylint: disable=raising-bad-type
        else:
            return self._result

    def get_result(self, timeout=None):
        with self._condition:
            if self._state == COMPLETED:
                return self._get_result()

            self._condition.wait(timeout)

            if self._state == COMPLETED:
                return self._get_result()
            else:
                raise TimeoutError()

    def get_exception(self, timeout=None):
        with self._condition:
            if self._state == COMPLETED:
                return self._exception

            self._condition.wait(timeout)

            if self._state == COMPLETED:
                return self._exception
            else:
                raise TimeoutError()


class ExecuteProgress(object):
    def __init__(self):
        self.successful_tasks = 0
        self._successful_lock = threading.Lock()
        self.failed_tasks = 0
        self._failed_lock = threading.Lock()
        self.finished_tasks = 0
        self._finished_lock = threading.Lock()
        self.total_tasks = 0

    def _successful_increment(self):
        with self._successful_lock:
            self.successful_tasks += 1
            return self.successful_tasks

    def _failed_increment(self):
        with self._failed_lock:
            self.failed_tasks += 1
            return self.failed_tasks

    def _finished_increment(self):
        with self._finished_lock:
            self.finished_tasks += 1
            return self.finished_tasks

    def get_successful_tasks(self):
        with self._successful_lock:
            return self.successful_tasks

    def get_failed_tasks(self):
        with self._failed_lock:
            return self.failed_tasks

    def get_finished_tasks(self):
        with self._finished_lock:
            return self.finished_tasks

    def get_total_tasks(self):
        return self.total_tasks


def _reportProgress(progress, interval, progressCallback):
    finishedTasks = progress._finished_increment()
    if finishedTasks % interval == 0 or finishedTasks == progress.get_total_tasks():
        successfulTasks = progress.get_successful_tasks()
        failedTasks = progress.get_failed_tasks()
        progressCallback(successfulTasks, failedTasks, progress.get_total_tasks())


def _checkBulkTasksPara(task_num, task_queue_size, task_interval, threshold):
    origine = [task_num, task_queue_size, task_interval, threshold]
    default = (
        const.DEFAULT_TASK_NUM, const.DEFAULT_TASK_QUEUE_SIZE, const.DEFAULT_BYTE_INTTERVAL, const.DEFAULT_MAXIMUM_SIZE)
    size = len(origine)
    for i in range(size):
        origine[i] = util.to_int(origine[i])
        if origine[i] is None or origine[i] <= 0:
            origine[i] = default[i]
    return tuple(origine)
