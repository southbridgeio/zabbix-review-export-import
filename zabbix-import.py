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
        if 'maps' in yml: return 'map'
        if 'screens' in yml: return 'screen'
        if 'hosts' in yml: return 'host'
        if 'value_maps' in yml: return 'valuemap'
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

def get_hostgroups_cache(zabbix):
    "Returns dict groupname=>groupid or None on error"
    result = zabbix.hostgroup.get(output=['groupid', 'name'])
    logging.debug(pformat(result))
    group2groupid = {}             # key: group name, value: groupid
    for group in result:
        group2groupid[group['name']] = group['groupid']
    return group2groupid

def get_template_cache(zabbix):
    "Return dict templatename=>templateid or None on error"
    result = zabbix.template.get(output=['templateid', 'host'])
    logging.debug(pformat(result))
    template2templateid = {} # key: template name, value: templateid
    for template in result:
        template2templateid[template['host']] = template['templateid']
    return template2templateid

def get_proxy_cache(zabbix):
    "Return dict proxyname=>proxyid or None on error"
    result = zabbix.proxy.get(output=["proxyid","host"])
    proxy2proxyid = {}          # key: proxy name, value: proxyid
    for proxy in result:
        proxy2proxyid[proxy['host']] = proxy['proxyid']
    return proxy2proxyid

def import_group(zabbix, yml):
    "Import hostgroup from YAML. Return created object, None on error, True if object already exist"
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

def import_proxy(zabbix, yml):
    "Import proxy form YAML. Return created object, None on error, True if object already exists"
    result = None
    try:
        result = zabbix.proxy.create(host=yml['host'], status=yml['status'], description=yml['description'], tls_accept=yml['tls_accept'], tls_connect=yml['tls_connect'], tls_issuer=yml['tls_issuer'], tls_psk=yml['tls_psk'], tls_psk_identity=yml['tls_psk_identity'], tls_subject=yml['tls_subject'])
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.error(e)
    return result

def import_host(zabbix, yml, group2groupid, template2templateid, proxy2proxyid):
    "Import host from YAML. Return created object, None on error, True if object already exists"
    result = None
    try:
        host = yml['hosts']['host']

        # set groupid(s) for new template:
        if isinstance(host['groups']['group'], dict):
            groups = [{'groupid': group2groupid[host['groups']['group']['name']]}]
        else:
            groups = []
            for group in host['groups']['group']:
                groups.append({'groupid': group2groupid[group['name']]})

        # set templateid(s) for linked template(s):
        if 'templates' in host:
            if isinstance(host['templates']['template'], dict):
                linked_templates = [{'templateid': template2templateid[host['templates']['template']['name']]}]
            else:
                linked_templates = []
                for t in host['templates']['template']:
                    linked_templates.append({'templateid': template2templateid[t['name']]})
        else:
            linked_templates = ""

        # set macroses for new template:
        if 'macros' in host:
            if isinstance(host['macros']['macro'], dict):
                macroses = [{"macro": host['macros']['macro']['macro'], "value": host['macros']['macro']['value']}]
            else:
                macroses = []
                for macro in host['macros']['macro']:
                    macroses.append({
                        "macro": macro['macro'],
                        "value": macro['value'],
                    })
        else:
            macroses = ""

        # set interfaces for new host:
        if 'interfaces' in host:
            if isinstance(host['interfaces']['interface'], dict):
                i = host['interfaces']['interface']
                interfaces = [{
                    "dns": i['dns'] if 'dns' in i else "",
                    "ip": i['ip'],
                    "main": i['default'],
                    "port": i['port'],
                    "type": i['type'],
                    "useip": i['useip'],
                    "bulk": i['bulk'],
                }]
            else:
                interfaces = []
                for i in host['interfaces']['interface']:
                    interfaces.append({
                        "dns": i['dns'] if 'dns' in i else "",
                        "ip": i['ip'],
                        "main": i['default'],
                        "port": i['port'],
                        "type": i['type'],
                        "useip": i['useip'],
                        "bulk": i['bulk'],
                    })
        else:
            interfaces = ""

        result = zabbix.host.create({
            "host": host['host'],
            "name": host['name'],
            "description": host['description'] if 'description' in host else "",
            "proxy_hostid": proxy2proxyid[host['proxy']['name']] if 'proxy' in host else 0,
            "status": host['status'],
            "tls_connect": host['tls_connect'] if 'tls_connect' in host else "",
            "tls_accept": host['tls_accept'] if 'tls_accept' in host else "",
            "tls_issuer": host['tls_issuer'] if 'tls_issuer' in host else "",
            "tls_subject": host['tls_subject'] if 'tls_subject' in host else "",
            "tls_psk_identity": host['tls_psk_identity'] if 'tls_psk_identity' in host else "",
            "tls_psk": host['tls_psk'] if 'tls_psk' in host else "",
            "interfaces": interfaces,
            "macros": macroses,
            "templates": linked_templates,
            "groups": groups,
            })
        # TBD/TODO/FIXME:
        # - httptests
        # - triggers
        # - items
        # - discovery_rules
        # - applications?
        # - graphs
    except ZabbixAPIException as e:
        if 'already exists' in str(e):
            result = True
        else:
            logging.error(e)
    return result

def import_template(zabbix, yml, group2groupid, template2templateid):
    "Import template from YAML. Return created object, None on error, True if object already exists"
    result = None
    try:
        new_template = yml['templates']['template']
        # set groupid(s) for new template:
        if isinstance(new_template['groups']['group'], dict):
            groups = [{'groupid': group2groupid[new_template['groups']['group']['name']]}]
        else:
            groups = []
            for group in new_template['groups']['group']:
                groups.append({'groupid': group2groupid[new_template['groups']['group'][group]['name']]})

        # set templateid(s) for linked template(s):
        if 'templates' in new_template:
            if isinstance(new_template['templates']['template'], dict):
                linked_templates = [{'templateid': template2templateid[new_template['templates']['template']['name']]}]
            else:
                linked_templates = []
                for t in new_template['templates']['template']:
                    linked_templates.append({'templateid': template2templateid[new_template['templates']['template'][t]['name']]})
        else:
            linked_templates = ""

        # set macroses for new template:
        if 'macros' in new_template:
            if isinstance(new_template['macros']['macro'], dict):
                macroses = [{"macro": new_template['macros']['macro']['macro'], "value": new_template['macros']['macro']['value']}]
            else:
                macroses = []
                for macro in new_template['macros']['macro']:
                    macroses.append({
                        "macro": macro['macro'],
                        "value": macro['value'],
                    })
        else:
            macroses = ""

        # create template:
        result = zabbix.template.create({
            "host": new_template['template'],
            "name": new_template['name'],
            "description": new_template['description'] if 'description' in new_template else "",
            "groups": groups,
            "templates": linked_templates,
            "macros": macroses,
        })
        logging.debug(pformat(result))
        # FIXME/TBD/TODO:
        # - items
        # - triggers
        # - discovery_rules
        # - applications?
        # - graphs
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def main(zabbix_, yaml_file, file_type, group_cache, template_cache, proxy_cache):
    "Main function: import YAML_FILE with type FILE_TYPE in ZABBIX_. Return None on error"
    api_version = zabbix_.apiinfo.version()
    logging.debug('Destination Zabbix server version: {}'.format(api_version))

    with open(yaml_file, 'r') as f:
        yml = yaml.safe_load(f)
    logging.debug('Got following YAML: {}'.format(yml))

    xml_exported = False
    op_result = None

    if 'zabbix_export' in yml:
        logging.debug('Loading from XML-exported YAML')
        xml_exported = True
        yml = yml['zabbix_export']
        if 'version' in yml:
            logging.debug('Source Zabbix server version: {}'.format(yml['version']))
    else:
        logging.debug('Loading from JSON-exported/raw YAML')

    if file_type == 'autoguess':
        if xml_exported: file_type = guess_yaml_type(yml, xml_exported=xml_exported)
        else: file_type = guess_yaml_type(yml, xml_exported=xml_exported)
        if file_type == 'autoguess':
            logging.error("Cant guess object type, exiting...")
            return None
        logging.info('Guessed file type: {}'.format(file_type))

    try:
        if file_type == "group":
            op_result = import_group(zabbix_, yml)
        elif file_type == "template":
            op_result = import_template(zabbix_, yml, group_cache, template_cache)
        elif file_type == "proxy":
            op_result = import_proxy(zabbix_, yml)
        elif file_type == "host":
            op_result = import_host(zabbix_, yml, group_cache, template_cache, proxy_cache)
        else:
            logging.error("This file type not yet implemented, exiting...")
    except Exception as e:
        logging.exception(pformat(e))
    if op_result == True:
        logging.info("Object already exist")
    elif op_result:
        logging.info("Operation completed successfully")
    else:
        logging.error("Operation failed")
    return op_result

def environ_or_required(key):
    "Argparse environment vars helper"
    if os.environ.get(key):
        return {'default': os.environ.get(key)}
    else:
        return {'required': True}

def parse_args():
    "Return parsed CLI args"
    parser = argparse.ArgumentParser(description="Import Zabbix object from YAML dump")
    parser.add_argument ("--debug", action="store_true", help="Show debug output")

    parser.add_argument("--zabbix-url", action="store", help="REQUIRED. May be in ZABBIX_URL env var", **environ_or_required('ZABBIX_URL'))
    parser.add_argument("--zabbix-username", action="store", help="REQUIRED. May be in ZABBIX_USERNAME env var", **environ_or_required('ZABBIX_USERNAME'))
    parser.add_argument("--zabbix-password", action="store", help="REQUIRED. May be in ZABBIX_PASSWORD env var", **environ_or_required('ZABBIX_PASSWORD'))

    parser.add_argument("--type", choices=[
        "autoguess",
        "host",
        "group",
        "template",
        "valuemap",
        "screen",
        "map",
        "service",
        "maintenance",
        "user",
        "mediatype",
        "usergroup",
        "action",
        "usermacro",
        "proxy",
        "image",
        "globalmacro"
    ], default="autoguess", help="Zabbix object type, default is %(default)s")
    parser.add_argument("FILE", help="YAML file to import from",nargs='+')

    args = parser.parse_args()
    return args

def init_logging(level):
    "Initialize logging"
    logger_format_string = '%(asctime)s %(levelname)-8s %(message)s'
    logging.basicConfig(level=level, format=logger_format_string, stream=sys.stdout)

if __name__ == "__main__":
    args = parse_args()
    level=logging.INFO
    if args.debug: level=logging.DEBUG
    init_logging(level=level)

    zabbix_ = get_zabbix_connection(args.zabbix_url, args.zabbix_username, args.zabbix_password)

    result = True               # Total success indicator

    try:
        # Fill caches:
        group2groupid = get_hostgroups_cache(zabbix_)
        template2templateid = get_template_cache(zabbix_)
        proxy2proxyid = get_proxy_cache(zabbix_)
        
        for f in args.FILE:
            logging.info("Trying to load Zabbix object (type: {}) from: {}".format(args.type, os.path.abspath(f)))
            r = main(zabbix_=zabbix_, yaml_file=f, file_type=args.type, group_cache=group2groupid, template_cache=template2templateid, proxy_cache=proxy2proxyid)
            if not r: result = False
    except Exception as e:
        result = False
        logging.exception(pformat(e))

    # Total success summary:
    if not result:
        logging.error("Some operations failed")
        sys.exit(1)
    logging.info("Done")
