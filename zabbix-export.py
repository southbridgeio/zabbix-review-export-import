#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sys
import xml.dom.minidom
from collections import OrderedDict

import anymarkup
import urllib3
import yaml
from pyzabbix import ZabbixAPI

urllib3.disable_warnings()


def remove_none(obj):
    """
    Remove None value from any object
    As is from https://stackoverflow.com/a/20558778/6753144
    :param obj:
    :return:
    """
    if isinstance(obj, (list, tuple, set)):
        return type(obj)(remove_none(x) for x in obj if x is not None)
    elif isinstance(obj, dict):
        return type(obj)((remove_none(k), remove_none(v))
                         for k, v in obj.items() if k is not None and v is not None)
    else:
        return obj


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


def order_data(data):
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = order_data(value)
        return OrderedDict(sorted(data.items()))
    elif isinstance(data, list):
        return [order_data(x) for x in data]
    else:
        return data


def dumps_json(object, data, directory, key='name', save_yaml=False,drop_keys=[]):
    """
    Create JSON or yaml file in folder
    """
    subfolder = os.path.join(directory, object)
    if not os.path.exists(subfolder):
        os.makedirs(subfolder)

    data = order_data(data)

    for item in data:
        logging.debug("Processing {}...".format(item[key]))
        if drop_keys:
            for drop_key in drop_keys:
                if drop_key in item:
                    del item[drop_key]
        txt = json.dumps(item, indent=4)

        # Remove bad characters from name
        name = item[key]
        name = re.sub(r'[\\/:"*?<>|]+', ' ', name)
        filename = '{}/{}.{}'.format(subfolder, name, 'yaml' if save_yaml else 'json')
        filename = os.path.abspath(filename)

        logging.debug("Write to file '{}'".format(filename))

        if save_yaml:
            txt = convert_to_yaml_without_none(txt)

        with open(filename, mode="w", encoding='utf-8', newline='\n') as file:
            file.write(txt)


def convert_to_yaml_without_none(txt):
    """
    Convert any object to OrderDict without None value
    """

    raw = anymarkup.parse(txt)
    raw = remove_none(raw)
    represent_dict_order = lambda self, data: self.represent_mapping('tag:yaml.org,2002:map', data.items())  # noqa
    yaml.add_representer(OrderedDict, represent_dict_order)
    txt = yaml.dump(raw, default_flow_style=False, width=10000, allow_unicode=True)
    return txt


def dump_xml(object, txt, name, directory, save_yaml=False):
    """
    Create XML or YAML in folder
    """
    folder = os.path.join(directory, object)
    if not os.path.exists(folder):
        os.makedirs(folder)

    # Remove bad characters from name
    name = re.sub(r'[\\/:"*?<>|]+', ' ', name)
    filename = '{}/{}.{}'.format(folder, name, 'yaml' if save_yaml else 'xml')
    filename = os.path.abspath(filename)

    # Remove bad lines from content
    # date
    txt = re.sub(r'<date>.*<\/date>', '', txt)
    # zabbix.version
    # txt = re.sub(r'<version>.*<\/version>', '', txt)

    # ppretty xml
    xml_ = xml.dom.minidom.parseString(txt)  # or xml.dom.minidom.parseString(xml_string)
    txt = xml_.toprettyxml(indent='  ', encoding='UTF-8')
    txt = txt.decode()

    # replace xml quot to normal readable "
    txt = txt.replace('&quot;', '"')

    if save_yaml:
        txt = convert_to_yaml_without_none(txt)

    logging.debug("Write to file '{}'".format(filename))
    with open(filename, mode="w", encoding='utf-8', newline='\n') as file:
        file.write(txt)


def main(zabbix_, save_yaml, directory):
    # XML
    # Standart zabbix xml export via API
    def export(zabbix_api, type, itemid, name):
        """
        Export one type: hosts, template, screen or other
        https://www.zabbix.com/documentation/4.0/manual/api/reference/configuration/export
        """
        logging.info("Export {}".format(type))
        items = zabbix_api.get()
        for item in items:
            logging.debug("Processing {}...".format(item[name]))
            txt = zabbix_.configuration.export(format='xml', options={type: [item[itemid]]})
            dump_xml(object=type, txt=txt, name=item[name], save_yaml=save_yaml, directory=directory)

    if yaml:
        logging.info("Convert all format to yaml")

    logging.info("Start export XML part...")
    export(zabbix_.hostgroup, 'groups', 'groupid', 'name')
    export(zabbix_.host, 'hosts', 'hostid', 'name')
    export(zabbix_.template, 'templates', 'templateid', 'name')
    export(zabbix_.valuemap, 'valueMaps', 'valuemapid', 'name')
    export(zabbix_.screen, 'screens', 'screenid', 'name')
    export(zabbix_.map, 'maps', 'sysmapid', 'name')

    # JSON
    # not support `export` method
    # Read more in https://www.zabbix.com/documentation/4.0/manual/api/reference/configuration/export
    logging.info("Start export JSON part...")
    logging.info("Processing action...")
    actions = zabbix_.action.get(selectOperations='extend', selectFilter='extend', selectRecoveryOperations='extend', selectAcknowledgeOperations='extend')
    dumps_json(object='actions', data=actions, save_yaml=save_yaml, directory=directory, drop_keys=["actionid"])

    logging.info("Processing mediatypes...")
    mediatypes = zabbix_.mediatype.get()
    dumps_json(object='mediatypes', data=mediatypes, key='description', save_yaml=save_yaml, directory=directory, drop_keys=["mediatypeidmediatypeid"])

    logging.info("Processing images...")
    images = zabbix_.image.get()
    dumps_json(object='images', data=images, save_yaml=save_yaml, directory=directory, drop_keys=["imageid"])

    logging.info("Processing usergroups...")
    usergroups = zabbix_.usergroup.get(selectRights='extend')
    dumps_json(object='usergroups', data=usergroups, save_yaml=save_yaml, directory=directory, drop_keys=["usrgrpid"])

    logging.info("Processing users...")
    users = zabbix_.user.get(selectMedias='extend', selectMediatypes='extend', selectUsrgrps='extend')
    dumps_json(object='users', data=users, key='alias', save_yaml=save_yaml, directory=directory, drop_keys=["userid"])

    logging.info("Processing proxy...")
    proxys = zabbix_.proxy.get(selectInterface='extend')
    dumps_json(object='proxy', data=proxys, key='host', save_yaml=save_yaml, directory=directory, drop_keys=["lastaccess", "proxyid"])

    logging.info("Processing global macroses...")
    global_macroses = zabbix_.usermacro.get(globalmacro='true')
    dumps_json(object='globalmacro', data=global_macroses, key='macro', save_yaml=save_yaml, directory=directory, drop_keys=["globalmacroid"])

    logging.info("Processing user macroses...")
    user_macroses = zabbix_.usermacro.get()
    dumps_json(object='usermacro', data=user_macroses, key='macro', save_yaml=save_yaml, directory=directory, drop_keys=["hostmacroid"])

    logging.info("Processing services...")
    services = zabbix_.service.get(selectParent='extend', selectTimes='extend')
    dumps_json(object='services', data=services, save_yaml=save_yaml, directory=directory, drop_keys=["serviceid"])

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--zabbix-url", action="store", required=True)
    parser.add_argument("--zabbix-username", action="store", required=True)
    parser.add_argument("--zabbix-password", action="store", required=True)

    parser.add_argument("--directory", action="store", default='./',
                        help="Directory where exported files will be saved")

    parser.add_argument("--save-yaml", action="store_true", help="All file's formats will be converted to YAML format")

    parser.add_argument ("--debug", action="store_true", help="Show debug output")

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

    logging.info("All files will be save in {}".format(os.path.abspath(args.directory)))
    main(zabbix_=zabbix_, save_yaml=args.save_yaml, directory=args.directory)
