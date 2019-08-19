#!/usr/bin/env python3
import argparse
import json
import logging
import os
import sys

import urllib3
urllib3.disable_warnings()
import yaml

from pyzabbix import ZabbixAPI, ZabbixAPIException
from pprint import pprint, pformat

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

def guess_yaml_type(yml, xml_exported=False):
    "Return string of guessed YAML file type (group, host, ...)"
    if xml_exported:
        if 'groups' in yml and not 'templates' in yml and not 'hosts' in yml: return 'group'
        if 'templates' in yml: return 'template'
        if 'value_maps' in yml: return 'valuemap'
        if 'maps' in yml: return 'map'
        if 'screens' in yml: return 'screen'
        if 'hosts' in yml: return 'host'
    else:
        if yml.keys() >= {"algorithm", "goodsla"}: return 'service'
        if yml.keys() >= {"proxy_hostid"}: return 'proxy'
        if yml.keys() >= {"maintenance_type"}: return 'maintenance'
        if yml.keys() >= {"alias"}: return 'user'
        if yml.keys() >= {"exec_path"}: return 'mediatype'
        if yml.keys() >= {"users_status"}: return 'usergroup'
        if yml.keys() >= {"operations"}: return 'action'
        if yml.keys() >= {"hostid", "macro"}: return 'usermacro'
        if yml.keys() >= {"macro"}: return 'globalmacro'
        if yml.keys() >= {"imagetype"}: return 'image'
        
    return 'autoguess'

def import_group(zabbix, yml):
    "Import hostgroup from YAML. Return created object or None on error"
    result = None
    try:
        result = zabbix.hostgroup.create(name=yml['groups']['group']['name'])
        logging.debug(pformat(result))
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.error(e)
    return result

def import_template(zabbix, yml):
    "Import template from YAML. Return created object or None on error"
    result = None
    try:
        # fill hostgroups cache:
        result = zabbix.hostgroup.get(output=['groupid', 'name'])
        logging.debug(pformat(result))
        group2groupid = {}             # key: group name, value: groupid
        for group in result:
            group2groupid[group['name']] = group['groupid']

        # fill templates cache:
        result = zabbix.template.get(output=['templateid', 'name'])
        logging.debug(pformat(result))
        template2templateid = {} # key: template name, value: templateid
        for template in result:
            template2templateid[template['name']] = template['templateid']

        # set groupid(s) for new template:
        if isinstance(yml['templates']['template']['groups']['group'], dict):
            groups = [{'groupid': group2groupid[yml['templates']['template']['groups']['group']['name']]}]
        else:
            groups = []
            for group in yml['templates']['template']['groups']['group']:
                groups.append({'groupid': group2groupid[yml['templates']['template']['groups']['group'][group]['name']]})

        # set templateid(s) for linked template(s):
        if 'templates' in yml['templates']['template']:
            if isinstance(yml['templates']['template']['templates']['template'], dict):
                templates = [{'templateid': template2templateid[yml['templates']['template']['templates']['template']['name']]}]
            else:
                templates = []
                for template in yml['templates']['template']['templates']['template']:
                    templates.append({'templateid': template2templateid[yml['templates']['template']['templates']['template'][template]['name']]})
        else:
            templates = ""

        # set macroses for new template:
        if 'macros' in yml['templates']['template']:
            if isinstance(yml['templates']['template']['macros']['macro'], dict):
                macroses = [{"macro": yml['templates']['template']['macros']['macro']['macro'], "value": yml['templates']['template']['macros']['macro']['value']}]
            else:
                macroses = []
                for macro in yml['templates']['template']['macros']['macro']:
                    macroses.append({
                        "macro": macro['macro'],
                        "value": macro['value'],
                    })
        else:
            macroses = ""

        # create template:
        result = zabbix.template.create({
            "host": yml['templates']['template']['template'],
            "name": yml['templates']['template']['name'],
            "description": yml['templates']['template']['description'] if 'description' in yml['templates']['template'] else "",
            "groups": groups,
            "templates": templates,
            "macros": macroses,
        })
        logging.debug(pformat(result))
        # FIXME/TBD/TODO:
        # - items
        # - triggers
        # - discovery_rules
        # - applications?
        # - graphs
        # - screens
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def main(zabbix_, yaml_file, file_type):
    api_version = zabbix_.apiinfo.version()
    logging.info('Destination Zabbix server version: {}'.format(api_version))

    with open(yaml_file, 'r') as f:
        yml = yaml.safe_load(f)
    logging.debug('Got following YAML: {}'.format(yml))

    xml_exported = False
    op_result = None

    if 'zabbix_export' in yml:
        logging.info('Loading from XML-exported YAML')
        xml_exported = True
        yml = yml['zabbix_export']
        if 'version' in yml:
            logging.info('Source Zabbix server version: {}'.format(yml['version']))
    else:
        logging.info('Loading from JSON-exported/raw YAML')

    if file_type == 'autoguess':
        if xml_exported: file_type = guess_yaml_type(yml, xml_exported=xml_exported)
        else: file_type = guess_yaml_type(yml, xml_exported=xml_exported)
        if file_type == 'autoguess':
            logging.error("Cant guess object type, exiting...")
            sys.exit(1)
        logging.info('Guessed file type: {}'.format(file_type))

    try:
        if file_type == "group":
            op_result = import_group(zabbix_, yml)
        elif file_type == "template":
            op_result = import_template(zabbix_, yml)
        else:
            logging.error("This file type not yet implemented, exiting...")
            sys.exit(2)
    except Exception as e:
        logging.exception(pformat(e))
    if op_result:
        logging.info("Done")
    else:
        logging.error("Operation failed")
        sys.exit(3)

def parse_args():
    "Return parsed CLI args"
    parser = argparse.ArgumentParser(description="Import Zabbix object from YAML dump")
    parser.add_argument ("--debug", action="store_true", help="Show debug output")
    parser.add_argument("--zabbix-url", action="store", required=True)
    parser.add_argument("--zabbix-username", action="store", required=True)
    parser.add_argument("--zabbix-password", action="store", required=True)
    parser.add_argument("--type", choices=["autoguess", "host", "group", "template", "valuemap", "screen", "map", "service", "maintenance", "user", "mediatype", "usergroup", "action", "usermacro", "proxy", "image", "globalmacro"], default="autoguess", help="Zabbix object type, default is %(default)s")
    parser.add_argument("FILE", help="YAML file to import from")

    args = parser.parse_args()
    return args

def init_logging(level):
    "Initialize logging"
    logger_format_string = '%(levelname)-8s %(message)s'
    logging.basicConfig(level=level, format=logger_format_string, stream=sys.stdout)

if __name__ == "__main__":
    args = parse_args()
    level=logging.INFO
    if args.debug: level=logging.DEBUG
    init_logging(level=level)

    zabbix_ = get_zabbix_connection(args.zabbix_url, args.zabbix_username, args.zabbix_password)

    logging.info("Trying to load Zabbix object (type: {}) from: {}".format(args.type, os.path.abspath(args.FILE)))
    main(zabbix_=zabbix_, yaml_file=args.FILE, file_type=args.type)
