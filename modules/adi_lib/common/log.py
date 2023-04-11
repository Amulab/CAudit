# coding=utf-8
"""
adi_lib.common.log

日志配置

版权所有 © 2019, 网星（北京）科技有限公司
"""

import logging
import logging.config
import os
import pathlib
import platform

# system_os = platform.system()
# if system_os == 'Windows':
#     log_file = "C:\\zawx\\logs\\plugin.log"
# elif system_os == "Linux":
#     log_file = "/home/zawx/logs/plugin.log"
# else:
#     log_file = "/tmp/plugin.log"
log_file = "./logs/plugin.log"

log_config = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
        'common': {
            # 'format': '%(asctime)s - %(name)s - %(filename)s - %(funcName)s - %(lineno)s - %(levelname)s - %(message)s'
            'format': '%(asctime)s - %(levelname)s - %(message)s'

        }
    },
    'handlers': {
        # 'console': {
        #     'class': 'logging.StreamHandler',
        #     'formatter': 'common',
        #     'stream': 'ext://sys.stdout',
        # },
        'plugin_handler': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'common',
            'filename': log_file,
            'encoding': 'utf-8',
            'maxBytes': 1024 * 1024 * 50,  # 50M
            'backupCount': 3
            # 'when': 'W0',   # 每周一切割日志
        },
    },
    'loggers': {
        # 'console': {
        #     'level': 'INFO',
        #     'handlers': ['console'],
        #     'propagate': 0
        # },
        'plugin': {
            'level': 'DEBUG',
            # 'handlers': ['plugin_handler', 'console'],
            'handlers': ['plugin_handler'],
            'propagate': 0
        },

    },
    # 'root': {
    #     'level': 'INFO',
    #     'handlers': ['console']
    # }
}

try:
    if not os.path.exists("logs"):
        os.makedirs("logs")
    if not os.path.exists(log_file):
        pathlib.Path(log_file).touch()
    logging.config.dictConfig(log_config)
except ValueError:
    print("[-] ./logs/plugin.log not exists")
    exit(-1)


def get_logger(log_name):
    return logging.getLogger(log_name)


logger = get_logger('plugin')
