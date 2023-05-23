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

import os
import sys
import logging.handlers
from modules.huaweiapi.obs.const import IS_WINDOWS, IS_PYTHON2

import threading

_lock = threading.Lock()

if IS_PYTHON2:
    from ConfigParser import ConfigParser
else:
    from configparser import ConfigParser

_handler = logging.handlers.RotatingFileHandler

CRITICAL = logging.CRITICAL
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG

LOG_LEVEL_DICT = {'CRITICAL': CRITICAL, 'ERROR': ERROR, 'WARNING': WARNING, 'INFO': INFO, 'DEBUG': DEBUG}


class LogConf(object):
    def __init__(self, config_file=None, sec='LOGCONF'):
        self.disable = True
        if config_file:
            str_path = os.path.abspath(config_file)
            if not os.path.exists(str_path):
                raise Exception('%s is not exist' % (str_path))

            cf = ConfigParser()
            read_ok = cf.read(config_file) if IS_PYTHON2 else cf.read(config_file, 'UTF-8')

            if read_ok:
                secs = cf.sections()
                if sec not in secs:
                    raise Exception('%s is not in secs:%s' % (sec, str(secs)))

                items = cf.items(sec)
                idict = {}
                for e in items:
                    idict[e[0]] = e[1]
                self.log_file_dir = idict.get('logfiledir', './')
                self.log_file_name = idict.get('logfilename', 'log.log')
                self.log_file_number = int(idict.get('logfilenumber', 0))
                self.log_file_size = int(idict.get('logfilesize', 0))
                self.print_log_to_console = int(idict.get('printlogtoconsole', 0))
                log_file_level = idict.get('logfilelevel')
                print_log_level = idict.get('printloglevel')
                self.log_file_level = LOG_LEVEL_DICT.get(log_file_level, DEBUG)
                self.print_log_level = LOG_LEVEL_DICT.get(print_log_level, DEBUG)
                self.disable = False


class NoneLogClient(object):
    def log(self, level, msg, *args, **kwargs):
        pass

    def close(self):
        pass


class LogClient(object):
    def __init__(self, log_config, log_name='OBS_LOGGER', display_name=None):
        if not log_config or not isinstance(log_config, LogConf):
            raise Exception('log config is not correct')
        self.log_config = log_config
        if display_name is None:
            display_name = log_name
        self.display_name = display_name
        self.logger = logging.getLogger(log_name)
        if not hasattr(self.logger, '_inited'):
            self.logger.setLevel(logging.DEBUG)
            if hasattr(self.logger, 'propagate'):
                self.logger.propagate = False
            if not log_config.disable:
                self.initLogger()
            self.logger._inited = 1

    def initLogger(self):
        if not os.path.exists(self.log_config.log_file_dir):
            with _lock:
                if not os.path.exists(self.log_config.log_file_dir):
                    os.makedirs(self.log_config.log_file_dir, 0o755)

        sep = '\\' if IS_WINDOWS else '/'
        logfilepath = self.log_config.log_file_dir + sep + self.log_config.log_file_name
        encoding = None if IS_PYTHON2 else 'UTF-8'
        formatter_handle = _handler(filename=logfilepath, encoding=encoding,
                                    maxBytes=1024 * 1024 * self.log_config.log_file_size,
                                    backupCount=self.log_config.log_file_number)
        formatter_handle.setLevel(self.log_config.log_file_level)
        formatter = logging.Formatter(
            '%(asctime)s|process:%(process)d|thread:%(thread)d|%(levelname)s|HTTP(s)+XML|%(message)s|')
        formatter_handle.setFormatter(formatter)

        self.logger.addHandler(formatter_handle)
        if self.log_config.print_log_to_console == 1:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_config.print_log_level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def close(self):
        for handle in self.logger.handlers:
            try:
                handle.close()
            except Exception:
                # ignore exception of log handle close.
                pass

    def log(self, level, msg, *args, **kwargs):
        base_back = sys._getframe().f_back
        func_name = base_back.f_code.co_name
        while func_name.lower() == 'log':
            base_back = base_back.f_back
            func_name = base_back.f_code.co_name
        line = base_back.f_lineno
        msg = '%(logger)s|%(name)s,%(lineno)d|' % {'logger': self.display_name, 'name': func_name,
                                                   'lineno': int(line)} + str(msg)

        if level == CRITICAL:
            self.logger.critical(msg, *args, **kwargs)
        elif level == ERROR:
            self.logger.error(msg, *args, **kwargs)
        elif level == WARNING:
            self.logger.warning(msg, *args, **kwargs)
        elif level == INFO:
            self.logger.info(msg, *args, **kwargs)
        elif level == DEBUG:
            self.logger.debug(msg, *args, **kwargs)
