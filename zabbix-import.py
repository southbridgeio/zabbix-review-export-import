#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys

import urllib3
urllib3.disable_warnings()

from pyzabbix import ZabbixAPI
from pprint import pprint

def get_zabbix_connection(zbx_url, zbx_user, zbx_password):
    """
    Sometimes pyzabbix and py-zabbix library can replace each other.
    This is a wrapper, we don't care about what pip-module we install.
    Return ZabbixAPI object
    """
    # pyzabbix library, with user\password in login method. It's GOOD library
    logging.debug("Try connect to Zabbix by pyzabbix...")
    try:
        zbx_pyzabbix = ZabbixAPI(zbx_url)
        zbx_pyzabbix.session.verify = False
        zbx_pyzabbix.login(zbx_user, zbx_password)
        return zbx_pyzabbix
    except Exception as e:
        logging.exception(e)

    # py-zabbix library, with user\password in ZabbixAPI
    logging.debug("Try connect to Zabbix by py-zabbix...")
    try:
        zbx_py_zabbix = ZabbixAPI(zbx_url, user=zbx_user, password=zbx_password)
        zbx_py_zabbix.session.verify = False
        return zbx_py_zabbix
    except Exception as e:
        logging.exception(e)
    # choose good API

    raise Exception("Some error in pyzabbix or py_zabbix module, see logs")

def main(zabbix_, yaml_file, file_type):
    api_version = zabbix_.apiinfo.version()
    logging.info('Destination Zabbix server version: {}'.format(api_version))

def parse_args():
    parser = argparse.ArgumentParser(description="Import Zabbix object from YAML dump")
    parser.add_argument ("--debug", action="store_true", help="Show debug output")
    parser.add_argument("--zabbix-url", action="store", required=True)
    parser.add_argument("--zabbix-username", action="store", required=True)
    parser.add_argument("--zabbix-password", action="store", required=True)
    parser.add_argument("--type", choices=["autoguess", "host", "group", "template", "valuemap", "screen", "map" ], default="autoguess", help="Zabbix object type, default is %(default)s")
    parser.add_argument("FILE", help="YAML file to import from")

    args = parser.parse_args()
    return args

def init_logging(level):
    logger_format_string = '%(levelname)-8s %(message)s'
    logging.basicConfig(level=level, format=logger_format_string, stream=sys.stdout)

if __name__ == "__main__":
    args = parse_args()
    level=logging.INFO
    if args.debug: level=logging.DEBUG
    init_logging(level=level)

    zabbix_ = get_zabbix_connection(args.zabbix_url, args.zabbix_username, args.zabbix_password)

    logging.info("Trying to load Zabbix {} from: {}".format(args.type, os.path.abspath(args.FILE)))
    main(zabbix_=zabbix_, yaml_file=args.FILE, file_type=args.type)
