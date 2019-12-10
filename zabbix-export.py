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
from pkg_resources import parse_version

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
        data.sort(key=lambda x: str(x))
        return [order_data(x) for x in data]
    else:
        return data


def dumps_json(object, data, directory, key='name', save_yaml=False,drop_keys=[]):
    """
    Create JSON or yaml file in folder
    """
    subfolder = os.path.join(directory, object.lower())
    if not os.path.exists(subfolder):
        os.makedirs(subfolder)

    data = order_data(data)

    for item in data:
        if isinstance(key, tuple): logging.debug("Processing {}...".format(item[key[0]]))
        else: logging.debug("Processing {}...".format(item[key]))
        if drop_keys:
            for drop_key in drop_keys:
                if drop_key in item:
                    del item[drop_key]
        txt = json.dumps(item, indent=4)

        # Remove bad characters from name
        if isinstance(key, tuple):
            name = "_".join(map(lambda x: item[x], key))
        else:
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
    txt = yaml.dump(raw, default_flow_style=False, width=10000, allow_unicode=True, explicit_start=True, explicit_end=True)
    return txt


def dump_xml(object, txt, name, directory, save_yaml=False):
    """
    Create XML or YAML in folder
    """
    folder = os.path.join(directory, object.lower())
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


def main(zabbix_, save_yaml, directory, only="all"):
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
            try:
                txt = zabbix_.configuration.export(format='xml', options={type: [item[itemid]]})
                dump_xml(object=type, txt=txt, name=item[name], save_yaml=save_yaml, directory=directory)
            except Exception as e:
                logging.error("Exception during export of template: {}".format(item[name]))
                logging.error(e)

    api_version = parse_version(zabbix_.apiinfo.version())
    logging.debug('Source Zabbix server version: {}'.format(api_version))

    if yaml:
        logging.info("Convert all format to yaml")

    logging.info("Start export XML part...")
    if only in ("all", "groups"): export(zabbix_.hostgroup, 'groups', 'groupid', 'name')
    if only in ("all", "hosts"): export(zabbix_.host, 'hosts', 'hostid', 'name')
    if only in ("all", "templates"): export(zabbix_.template, 'templates', 'templateid', 'name')
    if only in ("all", "valuemaps"): export(zabbix_.valuemap, 'valueMaps', 'valuemapid', 'name')
    if only in ("all", "maps"): export(zabbix_.map, 'maps', 'sysmapid', 'name')

    # JSON
    # not support `export` method
    # Read more in https://www.zabbix.com/documentation/4.0/manual/api/reference/configuration/export
    logging.info("Start export JSON part...")

    if only in ("all", "mediatypes", "users", "actions"):
        logging.info("Processing mediatypes...")
        mediatypes = zabbix_.mediatype.get()
        mediatypeid2mediatype = {"0": '__ALL__'}  # key: mediatypeid, value: mediatype name
        for mt in mediatypes:
            if api_version <= parse_version("4.4"):
                mediatypeid2mediatype[mt['mediatypeid']] = mt['description']
            else:
                mediatypeid2mediatype[mt['mediatypeid']] = mt['name']
        if api_version <= parse_version("4.4"):
            dumps_json(object='mediatypes', data=mediatypes, key='description', save_yaml=save_yaml, directory=directory, drop_keys=["mediatypeid"])
        else:
            dumps_json(object='mediatypes', data=mediatypes, key='name', save_yaml=save_yaml, directory=directory, drop_keys=["mediatypeid"])

    if only in ("all","images"):
        logging.info("Processing images...")
        images = zabbix_.image.get()
        dumps_json(object='images', data=images, save_yaml=save_yaml, directory=directory, drop_keys=["imageid"])

    if only in ("all", "usergroups", "screens", "actions", "dashboards"):
        logging.info("Processing usergroups...")
        usergroups = zabbix_.usergroup.get(selectRights='extend')
        usergroupid2usergroup = {}  # key: usergroupid, value: usergroup name
        for ug in usergroups:
            usergroupid2usergroup[ug['usrgrpid']] = ug['name']

        # existing hostgroups
        result = zabbix_.hostgroup.get(output=['groupid', 'name'])
        groupid2group = {}             # key: groupid, value: group name
        for group in result:
            groupid2group[group['groupid']] = group['name']

        # resolve hostgroupids:
        for usergroup in usergroups:
            usergroup['rights'] = [{"id": groupid2group[r['id']], "permission": r['permission']} for r in usergroup['rights']]
        dumps_json(object='usergroups', data=usergroups, save_yaml=save_yaml, directory=directory, drop_keys=["usrgrpid"])

    if only in ("all", "users", "screens", "actions", "dashboards"):
        logging.info("Processing users...")
        users = zabbix_.user.get(selectMedias='extend', selectUsrgrps='extend')
        userid2user = {}            # key: userid, value: user alias
        for u in users:
            userid2user[u['userid']] = u['alias']
            for ug in u['usrgrps']:
                del ug['usrgrpid']
            for m in u['medias']:
                del m['mediaid']
                del m['userid']
                m['mediatypeid'] = mediatypeid2mediatype[m['mediatypeid']] # resolve mediatype
        dumps_json(object='users', data=users, key='alias', save_yaml=save_yaml, directory=directory, drop_keys=["userid", "attempt_clock", "attempt_failed", "attempt_ip"])

    if only in ("all", "proxy"):
        logging.info("Processing proxy...")
        proxys = zabbix_.proxy.get(selectInterface='extend')
        dumps_json(object='proxy', data=proxys, key='host', save_yaml=save_yaml, directory=directory, drop_keys=["lastaccess", "proxyid"])

    if only in ("all", "globalmacro"):
        logging.info("Processing global macroses...")
        global_macroses = zabbix_.usermacro.get(globalmacro='true')
        dumps_json(object='globalmacro', data=global_macroses, key='macro', save_yaml=save_yaml, directory=directory, drop_keys=["globalmacroid"])

    # logging.info("Processing services...")
    # services = zabbix_.service.get(selectParent=['name'], selectTimes='extend')
    # dumps_json(object='services', data=services, key=('name', 'serviceid'), save_yaml=save_yaml, directory=directory, drop_keys=["status"])

    if only in ("all", "maintenances"):
        logging.info("Processing maintenances...")
        maintenances = zabbix_.maintenance.get(selectGroups=['name'], selectHosts=["name"], selectTimeperiods='extend')
        # sort hosts in maintenances by hostname to provide stable order:
        for m in maintenances:
            m['hosts'] = sorted(m['hosts'], key = lambda i: i['name']) # sort to stabilize dumps
            m['groups'] = sorted(m['groups'], key = lambda i: i['name']) # sort to stabilize dumps
            for h in m['hosts']:
                del h['hostid']
            for g in m['groups']:
                del h['groupid']
            for tp in m['timeperiods']:
                del tp['timeperiodid']
            m['hostids'] = m.pop('hosts') # rename for easy import
            m['groupids'] = m.pop('groups') # rename for easy import
        dumps_json(object='maintenances', data=maintenances, save_yaml=save_yaml, directory=directory, drop_keys=["maintenanceid"])

    if only in ("all", "screens", "dashboards"):
        logging.info("Processing screens...")

        graphid2graph = {}          # key: graphid, value: "hostname,graphname"
        graphs = zabbix_.graph.get(output=['graphid', 'name'], selectHosts=["name"], templated=False)
        for g in graphs:
            if g['hosts']:          # graph not in template
                graphid2graph[g['graphid']] = '{},{}'.format(g['hosts'][0]['name'],g['name'])

        itemid2item = {}            # key: itemid, value: "hostname, key_"
        items = zabbix_.item.get(output=['key_', 'itemid'], selectHosts=["name"], webitems=True)
        for i in items:
            if i['hosts']:          # item not in template
                itemid2item[i['itemid']] = '{},{}'.format(i['hosts'][0]['name'],i['key_'])

        itemid2proto = {}           # key: itemid, value: "hostname, key_"
        itemprototypes = zabbix_.itemprototype.get(output=['key_', 'itemid'], selectHosts=['name'])
        for i in itemprototypes:
            if i['hosts']:
                itemid2proto[i['itemid']] = '{},{}'.format(i['hosts'][0]['name'],i['key_'])

        graphid2proto = {}          # key: graphid, value: "hostname, graphname"
        graphprototypes = zabbix_.graphprototype.get(output=['graphid', 'name'], selectHosts=['name'])
        for gp in graphprototypes:
            if gp['hosts']:
                graphid2proto[gp['graphid']] = '{},{}'.format(gp['hosts'][0]['name'],gp['name'])

        screens = zabbix_.screen.get(selectUsers='extend', selectUserGroups='extend', selectScreenItems='extend')
        for screen in screens:
            # resolve users/usergroups/screenitems:
            screen['userid'] = userid2user[screen['userid']]
            screen['users'] = [{'permission': user['permission'], 'userid': userid2user[user['userid']]} for user in screen['users']]
            screen['userGroups'] = [{"permission": group['permission'], "usrgrpid": usergroupid2usergroup[group['usrgrpid']]} for group in screen['userGroups']]
            for si in screen['screenitems']:
                del si['screenid']
                del si['screenitemid']
                if si['resourcetype'] == '0': # graph
                    si['resourceid'] = graphid2graph[si['resourceid']]
                elif si['resourcetype'] == '1':                            # simple graph
                    si['resourceid'] = itemid2item[si['resourceid']]
                elif si['resourcetype'] == '2':                            # map
                    pass
                elif si['resourcetype'] == '3':                            # plain text
                    pass                      # FIXME
                elif si['resourcetype'] == '5':                            # triggers info
                    pass
                elif si['resourcetype'] == '8':                            # screen
                    pass
                elif si['resourcetype'] == '9':                            # triggers overview
                    pass
                elif si['resourcetype'] == '10':                           # data overview
                    si['resourceid'] = groupid2group[si['resourceid']]
                elif si['resourcetype'] == '14':                           # latest host group issues
                    pass
                elif si['resourcetype'] == '16':                           # latest host issues
                    pass
                elif si['resourcetype'] == '19':                           # simple graph prototype
                    si['resourceid'] = itemid2proto[si['resourceid']]
                elif si['resourcetype'] == '20':                           # graph prototype
                    si['resourceid'] = graphid2proto[si['resourceid']]

        dumps_json(object='screens', data=screens, save_yaml=save_yaml, directory=directory, drop_keys=["screenid"])

    if only in ("all", "actions", "usermacro"):
        logging.info("Processing action...")
        actions = zabbix_.action.get(selectOperations='extend', selectFilter='extend', selectRecoveryOperations='extend', selectAcknowledgeOperations='extend')
        # existing templates
        result = zabbix_.template.get(output=["host", "templateid"])
        templateid2template = {}   # key: templateid, value: template name
        for template in result:
            templateid2template[template['templateid']] = template['host']
        # existing hosts
        result = zabbix_.host.get(output=["name", "hostid"])
        hostid2host = {}            # key: hostid, value: host name
        for host in result:
            hostid2host[host['hostid']] = host['name']
        # existing triggers
        result = zabbix_.trigger.get(output=['description', 'triggerid'], selectHosts=['name'])
        triggerid2trigger = {} # key: triggerid, value: {description: trigger description, host: host name}
        for trigger in result:
            triggerid2trigger[trigger['triggerid']] = {
                'description': trigger['description'],
                'host': trigger['hosts'][0]['name'] if trigger['hosts'] else "",
                }

        # resolve templateids/groupids/mediatypeids/userids/usergroupids:
        for action in actions:
            action['filter']['conditions'] = sorted(action['filter']['conditions'], key = lambda i: i['formulaid']) # sort to stabilize dumps
            action['filter']['formula'] = action['filter']['eval_formula']
            del action['filter']['eval_formula']
            action['recovery_operations'] = action.pop('recoveryOperations') # rename key for easy import
            action['acknowledge_operations'] = action.pop('acknowledgeOperations') # rename key for easy import
            for action_type in ('operations', 'acknowledge_operations', 'recovery_operations'):
                for op in action[action_type]:
                    del op['actionid']
                    del op['operationid']
                    if 'optemplate' in op:
                        for aa in op['optemplate']:
                            aa['templateid'] = templateid2template[aa['templateid']]
                            del aa['operationid']
                    if 'opgroup' in op:
                        for aa in op['opgroup']:
                            aa['groupid'] = groupid2group[aa['groupid']]
                            del aa['operationid']
                    if 'opmessage' in op:
                        op['opmessage']['mediatypeid'] = mediatypeid2mediatype[op['opmessage']['mediatypeid']]
                        del op['opmessage']['operationid']
                    if 'opmessage_grp' in op:
                        for aa in op['opmessage_grp']:
                            aa['usrgrpid'] = usergroupid2usergroup[aa['usrgrpid']]
                            del aa['operationid']
                    if 'opmessage_usr' in op:
                        for aa in op['opmessage_usr']:
                            aa['userid'] = userid2user[aa['userid']]
                            del aa['operationid']
                    if 'opcommand' in op:
                        del op['opcommand']['operationid']
                    if 'opcommand_hst' in op:
                        for aa in op['opcommand_hst']:
                            if str(aa['hostid']) != '0': # '0' means current host
                                aa['hostid'] = hostid2host[aa['hostid']]
                            del aa['operationid']
                            del aa['opcommand_hstid']
                    if 'opcommand_grp' in op:
                        for aa in op['opcommand_grp']:
                            aa['groupid'] = groupid2group[aa['groupid']]
                            del aa['operationid']
                            del aa['opcommand_grpid']
                    if 'opconditions' in op:
                        for aa in op['opconditions']:
                            del aa['operationid']
                            del aa['opconditionid']
            for condition in action['filter']['conditions']:
                if condition['conditiontype'] == '0': # hostgroup
                    condition['value'] = groupid2group[condition['value']]
                if condition['conditiontype'] == '1': # host
                    condition['value'] = hostid2host[condition['value']]
                if condition['conditiontype'] == '13': # template
                    condition['value'] = templateid2template[condition['value']]
                if condition['conditiontype'] == '2': # trigger
                    condition['value2'] = triggerid2trigger[condition['value']]['host']
                    condition['value'] = triggerid2trigger[condition['value']]['description']

        dumps_json(object='actions', data=actions, save_yaml=save_yaml, directory=directory, drop_keys=["actionid"])

    if only in ("all", "usermacro"):
        logging.info("Processing user macroses...")
        user_macroses = zabbix_.usermacro.get()
        # resolve hostids:
        for umacro in user_macroses:
            try: umacro['hostid'] = hostid2host[umacro['hostid']]
            except KeyError:
                umacro['hostid'] = templateid2template[umacro['hostid']]
        dumps_json(object='usermacro', data=user_macroses, key=('macro', 'hostid'), save_yaml=save_yaml, directory=directory, drop_keys=["hostmacroid"])

    if only in ("all", "dashboards"):
        logging.info("Processing dashboards...")
        dashboards = zabbix_.dashboard.get(selectWidgets="extend", selectUsers="extend", selectUserGroups="extend")
        for d in dashboards:
            d['userid'] = userid2user[d['userid']]
            for u in d['users']:
                u['userid'] = userid2user[u['userid']]
            for ug in d['userGroups']:
                ug['usrgrpid'] = usergroupid2usergroup[ug['usrgrpid']]
            for w in d['widgets']:
                del w['widgetid']
                w['fields'] = sorted(w['fields'], key = lambda i: i['name']) # sort to stabilize dumps
                for f in w['fields']:
                    if f['name'] == 'graphid':
                        f['value'] = graphid2graph[f['value']]

        dumps_json(object='dashboards', data=dashboards, directory=directory, save_yaml=save_yaml, drop_keys=['dashboardid'])

def environ_or_required(key):
    "Argparse environment vars helper"
    if os.environ.get(key):
        return {'default': os.environ.get(key)}
    else:
        return {'required': True}

def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--zabbix-url", action="store", help="REQUIRED. May be in ZABBIX_URL env var", **environ_or_required('ZABBIX_URL'))
    parser.add_argument("--zabbix-username", action="store", help="REQUIRED. May be in ZABBIX_USERNAME env var", **environ_or_required('ZABBIX_USERNAME'))
    parser.add_argument("--zabbix-password", action="store", help="REQUIRED. May be in ZABBIX_PASSWORD env var", **environ_or_required('ZABBIX_PASSWORD'))

    parser.add_argument("--directory", action="store", default='./',
                        help="Directory where exported files will be saved")

    parser.add_argument("--save-yaml", action="store_true", help="All file's formats will be converted to YAML format")

    parser.add_argument ("--debug", action="store_true", help="Show debug output")

    parser.add_argument("--only", choices=[
        "all",
        "hosts",
        "groups",
        "templates",
        "valuemaps",
        "maps",
        "mediatypes",
        "images",
        "usergroups",
        "users",
        "proxy",
        "globalmacro",
        "maintenances",
        "screens",
        "actions",
        "usermacro",
        "dashboards",
    ], default="all", help="Only object type that will be exported, default is %(default)s")

    args = parser.parse_args()
    return args


def init_logging(level):
    logger_format_string = '%(asctime)s %(levelname)-8s %(message)s'
    logging.basicConfig(level=level, format=logger_format_string, stream=sys.stdout)


if __name__ == "__main__":
    args = parse_args()
    level=logging.INFO
    if args.debug: level=logging.DEBUG
    init_logging(level=level)

    zabbix_ = get_zabbix_connection(args.zabbix_url, args.zabbix_username, args.zabbix_password)

    logging.info("All files will be save in {}".format(os.path.abspath(args.directory)))
    main(zabbix_=zabbix_, save_yaml=args.save_yaml, directory=args.directory, only=args.only)
