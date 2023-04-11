import json
import sys

from utils.consts import module_base_class
from utils.logger import output


def get_user_module() -> str:
    mod = ""
    for a in sys.argv:
        if a in module_base_class.keys():
            mod = a
    return mod


def get_user_exploit_input() -> str:
    u_plugin = ""

    try:
        for a in sys.argv:
            if a == "exploit":
                u_plugin = sys.argv[sys.argv.index(a)+1]
    except IndexError:
        output.error("Please specify exploit type plugin, use --help to list plugins")
        sys.exit(-2)
    return u_plugin


# def read_json_file(file_path: str) -> dict:
#     try:
#         output.debug(f"Reading {file_path}")
#
#         with open(file_path, 'r') as fcc_file:
#             fcc_data = json.load(fcc_file)
#             return fcc_data
#     except FileNotFoundError:
#         output.error(f"Can't found json file {file_path}")
#         sys.exit(-1)

