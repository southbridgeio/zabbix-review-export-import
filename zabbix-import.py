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
import random, string
from pkg_resources import parse_version

def randompassword():
    return ''.join([random.choice(string.printable) for _ in range(random.randint(8, 10))])

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
        group2groupid[group['name']] = int(group['groupid'])
    return group2groupid

def get_template_cache(zabbix):
    "Return dict templatename=>templateid or None on error"
    result = zabbix.template.get(output=['templateid', 'host'])
    logging.debug(pformat(result))
    template2templateid = {} # key: template name, value: templateid
    for template in result:
        template2templateid[template['host']] = int(template['templateid'])
    return template2templateid

def get_proxy_cache(zabbix):
    "Return dict proxyname=>proxyid or None on error"
    result = zabbix.proxy.get(output=["proxyid","host"])
    proxy2proxyid = {}          # key: proxy name, value: proxyid
    for proxy in result:
        proxy2proxyid[proxy['host']] = int(proxy['proxyid'])
    return proxy2proxyid

def get_hosts_cache(zabbix):
    "Return dict hostname=>hostid or None on error"
    result = zabbix.host.get(output=["host", "hostid"])
    host2hostid = {}            # key: host name, value: hostid
    for host in result:
        host2hostid[host["host"]] = int(host['hostid'])
    return host2hostid

def get_usergroup_cache(zabbix):
    "Return dict usergroupname=>usergroupid or None on error"
    result = zabbix.usergroup.get(output=["name", "usrgrpid"])
    usergroup2usergroupid = {}  # key: usergroup name, value: usrgrpid
    for ug in result:
        usergroup2usergroupid[ug['name']] = int(ug['usrgrpid'])
    return usergroup2usergroupid

def get_users_cache(zabbix):
    "Return dict username=>userid or None on error"
    result = zabbix.user.get(output=["alias", "userid"])
    user2userid = {}            # key: user alias, value: userid
    for u in result:
        user2userid[u['alias']] = int(u['userid'])
    return user2userid

def get_mediatype_cache(zabbix):
    "Return dict mediatype=>mediatypeid or None on error"
    result = zabbix.mediatype.get(output=["description", "mediatypeid"])
    mediatype2mediatypeid = {'__ALL__': '0'}  # key: mediatype name, value: mediatypeid
    for mt in result:
        mediatype2mediatypeid[mt['description']] = int(mt['mediatypeid'])
    return mediatype2mediatypeid

def get_screen_cache(zabbix):
    "Return dict screen name=>screenid or None on error"
    result = zabbix.screen.get(output=["name", "screenid"])
    screen2screenid = {}  # key: screen name, value: screenid
    for sc in result:
        screen2screenid[sc['name']] = int(sc['screenid'])
    return screen2screenid

def get_action_cache(zabbix):
    "Return dict action name=>actionid or None on error"
    result = zabbix.action.get(output=["name", "actionid"])
    action2actionid = {}        # key: action name, value: actionid
    for a in result:
        action2actionid[a['name']] = int(a['actionid'])
    return action2actionid

def get_trigger_cache(zabbix):
    "Return dict trigger name=>triggerid or None on error"
    result = zabbix.trigger.get(output=['description', 'triggerid'], selectHosts=['name'])
    trigger2triggerid = {}        # key: (trigger description, host name), value: triggerid
    for t in result:
        trigger2triggerid[(t['description'],t['hosts'][0]['name'])] = int(t['triggerid'])
    return trigger2triggerid

def import_group(zabbix, yml, group2groupid):
    "Import hostgroup from YAML. Return created object, None on error, True if object already exist"
    g = yml['groups']['group']
    if g['name'] in group2groupid: return True # skip existing objects

    result = None
    try:
        result = zabbix.hostgroup.create(name=g['name'])
        logging.debug(pformat(result))
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.error(e)
            result = False
    return result

def import_proxy(zabbix, yml, proxy2proxyid):
    "Import proxy form YAML. Return created object, None on error, True if object already exists"
    if yml['host'] in proxy2proxyid: return True # skip existing objects

    result = None
    try:
        result = zabbix.proxy.create(host=yml['host'], status=yml['status'], description=yml['description'], tls_accept=yml['tls_accept'], tls_connect=yml['tls_connect'], tls_issuer=yml['tls_issuer'], tls_psk=yml['tls_psk'], tls_psk_identity=yml['tls_psk_identity'], tls_subject=yml['tls_subject'])
        logging.debug(pformat(result))
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.error(e)
            result = False
    return result

def import_host(api_version, zabbix, yml, group2groupid, template2templateid, proxy2proxyid, host2hostid):
    "Import host from YAML. Return created object, None on error, True if object already exists"
    result = None
    try:
        host = yml['hosts']['host']
        if host['host'] in host2hostid: return True # skip existing objects

        # set groupid(s) for new template:
        if isinstance(host['groups']['group'], dict): host['groups']['group'] = [host['groups']['group']]
        groups = [{'groupid': group2groupid[group['name']]} for group in host['groups']['group']]

        # set templateid(s) for linked template(s):
        if 'templates' in host:
            if isinstance(host['templates']['template'], dict): host['templates']['template'] = [host['templates']['template']]
            linked_templates = [{'templateid': template2templateid[t['name']]} for t in host['templates']['template']]
        else:
            linked_templates = ""

        # set macroses for new template:
        if 'macros' in host:
            if isinstance(host['macros']['macro'], dict): host['macros']['macro'] = [host['macros']['macro']]
            macroses = [{"macro": macro['macro'], "value": macro['value'] } for macro in host['macros']['macro']]
        else:
            macroses = ""

        # set interfaces for new host:
        if 'interfaces' in host:
            if isinstance(host['interfaces']['interface'], dict): host['interfaces']['interface'] = [host['interfaces']['interface']]
            interfaces = [{"dns": i['dns'] if 'dns' in i else "", "ip": i['ip'], "main": i['default'], "port": i['port'], "type": i['type'], "useip": i['useip'], "bulk": i['bulk']} for i in host['interfaces']['interface']]
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
        logging.debug(pformat(result))

        new_hostid = result['hostids'][0] # ID of created host
        key2itemid = {}     # key: item key, value: itemid (will be used for dependent items and graph prototypes)

        if 'applications' not in host:
            host['applications'] = {'application': []}
        if isinstance(host['applications']['application'], dict): host['applications']['application'] = [host['applications']['application']]
        apps = zabbix.application.get(hostids=new_hostid, output=['name', 'applicationid'])
        app2id = {}         # key: app name, value: app id
        for app in apps:
            app2id[app['name']] = app['applicationid']
        for app in host['applications']['application']:
            if app['name'] not in app2id:
                new_app = zabbix.application.create(name=app['name'], hostid=new_hostid) # create missed apps
                app2id[app['name']] = new_app['applicationids'][0] # save new app id for future use in items

        if 'items' in host or 'discovery_rules' in host:
            # hack: use default interface for items
            iface = zabbix.hostinterface.get(output="interfaceid", hostids=new_hostid, filter={"main": 1})
            new_ifaceid = iface[0]['interfaceid']

        if 'items' in host:
            if isinstance(host['items']['item'], dict): host['items']['item'] = [host['items']['item']]

            # create non-dependent items:
            for item in filter(lambda x: x['type'] != 18,host['items']['item']):
                if 'applications' in item:
                    if isinstance(item['applications']['application'], dict):
                        item['applications']['application'] = [item['applications']['application']]
                else:
                    item['applications'] = {'application': []}
                if 'preprocessing' in item:
                    if isinstance(item['preprocessing']['step'], dict): item['preprocessing']['step'] = [item['preprocessing']['step']]
                    for step in item['preprocessing']['step']:
                        if 'params' not in step: step['params'] = ''
                    if api_version >= parse_version("4.0"):
                        for step in item['preprocessing']['step']:
                            if 'error_handler' not in step: step['error_handler'] = 0
                            if 'error_handler_params' not in step: step['error_handler_params'] = ""

                new_item = zabbix.item.create({
                    "delay": item['delay'],
                    "hostid": new_hostid,
                    "interfaceid": new_ifaceid,
                    "key_": item['key'],
                    "name": item['name'],
                    "type": item['type'],
                    "value_type": item['value_type'],
                    "history": item['history'],
                    "trends": item['trends'],
                    "status": item['status'],
                    "units": item['units'] if 'units' in item else "",
                    "authtype": item['authtype'],
                    "description": item['description'] if 'description' in item else "",
                    "snmpv3_securitylevel": item['snmpv3_securitylevel'],
                    "snmpv3_authprotocol": item['snmpv3_authprotocol'],
                    "snmpv3_privprotocol": item['snmpv3_privprotocol'],
                    "snmp_community": item['snmp_community'] if 'snmp_community' in item else "",
                    "snmp_oid": item['snmp_oid'] if 'snmp_oid' in item else "",
                    "applications": [app2id[x['name']] for x in item['applications']['application']],
                    "preprocessing": item['preprocessing']['step'] if 'preprocessing' in item else [],
                })

            # fetch itemids for master items:
            if list(filter(lambda x: x['type'] == 18,host['items']['item'])): # only fetch itemids if there is dependent items
                for item in zabbix.item.get(output=["key_", "itemid"], hostids=new_hostid):
                    key2itemid[item['key_']] = item['itemid']

            # create dependent items:
            for item in filter(lambda x: x['type'] == 18,host['items']['item']):
                if 'applications' in item:
                    if isinstance(item['applications']['application'], dict):
                        item['applications']['application'] = [item['applications']['application']]
                else:
                    item['applications'] = {'application': []}
                if 'preprocessing' in item:
                    if isinstance(item['preprocessing']['step'], dict): item['preprocessing']['step'] = [item['preprocessing']['step']]
                    for step in item['preprocessing']['step']:
                        if 'params' not in step: step['params'] = ''
                    if api_version >= parse_version("4.0"):
                        for step in item['preprocessing']['step']:
                            if 'error_handler' not in step: step['error_handler'] = 0
                            if 'error_handler_params' not in step: step['error_handler_params'] = ""

                new_item = zabbix.item.create({
                    "delay": item['delay'],
                    "hostid": new_hostid,
                    "interfaceid": new_ifaceid,
                    "key_": item['key'],
                    "name": item['name'],
                    "type": item['type'],
                    "value_type": item['value_type'],
                    "history": item['history'],
                    "trends": item['trends'],
                    "status": item['status'],
                    "master_itemid": key2itemid[item['master_item']['key']],
                    "units": item['units'] if 'units' in item else "",
                    "authtype": item['authtype'],
                    "description": item['description'] if 'description' in item else "",
                    "snmpv3_securitylevel": item['snmpv3_securitylevel'],
                    "snmpv3_authprotocol": item['snmpv3_authprotocol'],
                    "snmpv3_privprotocol": item['snmpv3_privprotocol'],
                    "snmp_community": item['snmp_community'] if 'snmp_community' in item else "",
                    "snmp_oid": item['snmp_oid'] if 'snmp_oid' in item else "",
                    "applications": [app2id[x['name']] for x in item['applications']['application']],
                    "preprocessing": item['preprocessing']['step'] if 'preprocessing' in item else [],
                })

        if 'httptests' in host:
            if isinstance(host['httptests']['httptest'], dict): host['httptests']['httptest'] = [host['httptests']['httptest']]
            for test in host['httptests']['httptest']:
                if isinstance(test['steps']['step'], dict): test['steps']['step'] = [test['steps']['step']]
                if 'headers' in test:
                    if isinstance(test['headers']['header'], dict): test['headers']['header'] = [test['headers']['header']]
                no = 0
                for step in test['steps']['step']:
                    if 'headers' in step:
                        if isinstance(step['headers']['header'], dict): step['headers']['header'] = [step['headers']['header']]
                        step['headers'] = step['headers']['header']
                    step['name'] = str(step['name'])     # convert to string
                    if 'no' not in step: step['no'] = no # step counter
                    if 'status_codes' in step: step['status_codes'] = str(step['status_codes']) # convert to string
                    if 'required' in step: step['required'] = str(step['required'])
                    if 'query_fields' in step:
                        if isinstance(step['query_fields']['query_field'], dict): step['query_fields']['query_field'] = [step['query_fields']['query_field']]
                        step['query_fields'] = step['query_fields']['query_field']
                        for field in step['query_fields']:
                            if 'value' not in field: field['value'] = "" # add missing "value" field
                            field["value"] = str(field["value"]) # convert to string

                new_httptest = zabbix.httptest.create({
                    "name": test['name'],
                    "hostid": new_hostid,
                    "delay": test['delay'] if 'delay' in test else "1m",
                    "headers": test['headers']['header'] if 'headers' in test else [],
                    "retries": test['attempts'],
                    "steps": test['steps']['step'],
                    "agent": test['agent'] if 'agent' in test else "Zabbix",
                    "status": test['status'] if 'status' in test else 0,
                    "authentication": test['authentication'] if 'authentication' in test else 0,
                    "http_password": test['http_password'] if 'http_password' in test else "",
                    "http_proxy": test['http_proxy'] if 'http_proxy' in test else "",
                    "http_user": test['http_user'] if 'http_user' in test else "",
                    "ssl_cert_file": test['ssl_cert_file'] if 'ssl_cert_file' in test else "",
                    "ssl_key_file": test['ssl_key_file'] if 'ssl_key_file' in test else "",
                    "ssl_key_password": test['ssl_key_password'] if 'ssl_key_password' in test else "",
                    "verify_host": test['verify_host'] if 'verify_host' in test else 0,
                    "verify_peer": test['verify_peer'] if 'verify_peer' in test else 0,
                })

        if 'triggers' in yml:
            trigger2triggerid = get_trigger_cache(zabbix) # get fresh trigger cache
            if isinstance(yml['triggers']['trigger'], dict): yml['triggers']['trigger'] = [yml['triggers']['trigger']]
            for trigger in yml['triggers']['trigger']:
                trigger['comments'] = trigger['description'] if 'description' in trigger else ""
                trigger['description'] = trigger['name']
                del trigger['name']
                if 'url' in trigger:
                    if '://' not in trigger['url']: trigger['url'] = "https://" + trigger['url'] # add missed scheme if needed
                if 'dependencies' in trigger: # resolve dependencies
                    if isinstance(trigger['dependencies']['dependency'], dict): trigger['dependencies']['dependency'] = [trigger['dependencies']['dependency']]
                    trigger['dependencies'] = [{"triggerid": trigger2triggerid[(x['name'],host['name'])]} for x in trigger['dependencies']['dependency']]
                new_trigger = zabbix.trigger.create(trigger)

        if 'discovery_rules' in host:
            if isinstance(host['discovery_rules']['discovery_rule'], dict): host['discovery_rules']['discovery_rule'] = [host['discovery_rules']['discovery_rule']]
            for rule in host['discovery_rules']['discovery_rule']:
                rule['delay'] = str(rule['delay']) # convert to string
                rule['hostid'] = new_hostid
                rule['interfaceid'] = new_ifaceid
                rule['key_'] = rule['key']
                del rule['key']
                if 'filter' in rule:
                    if 'conditions' not in rule['filter']: del rule['filter']

                if 'filter' in rule:
                    if isinstance(rule['filter']['conditions']['condition'], dict): rule['filter']['conditions']['condition'] = [rule['filter']['conditions']['condition']]
                    rule['filter']['conditions'] = rule['filter']['conditions']['condition']

                new_rule = zabbix.discoveryrule.create(rule)
                new_ruleid = new_rule['itemids'][0]

                if 'item_prototypes' in rule:
                    if isinstance(rule['item_prototypes']['item_prototype'], dict): rule['item_prototypes']['item_prototype'] = [rule['item_prototypes']['item_prototype']]
                    for item_prot in rule['item_prototypes']['item_prototype']:
                        item_prot['ruleid'] = new_ruleid
                        item_prot['key_'] = item_prot['key']
                        del item_prot['key']
                        item_prot['hostid'] = new_hostid
                        item_prot['interfaceid'] = new_ifaceid

                        if 'preprocessing' in item_prot:
                            if isinstance(item_prot['preprocessing']['step'], dict): item_prot['preprocessing']['step'] = [item_prot['preprocessing']['step']]
                            for step in item_prot['preprocessing']['step']:
                                if 'params' not in step: step['params'] = ''
                            if api_version >= parse_version("4.0"):
                                for step in item_prot['preprocessing']['step']:
                                    if 'error_handler' not in step: step['error_handler'] = 0
                                    if 'error_handler_params' not in step: step['error_handler_params'] = ""
                            item_prot['preprocessing'] = item_prot['preprocessing']['step']

                        if 'applications' in item_prot:
                            if isinstance(item_prot['applications']['application'], dict): item_prot['applications']['application'] = [item_prot['applications']['application']]
                            item_prot['applications'] = [app2id[app['name']] for app in item_prot['applications']['application']] # resolve applications
                        new_item_prot = zabbix.itemprototype.create(item_prot)

                if 'trigger_prototypes' in rule:
                    if isinstance(rule['trigger_prototypes']['trigger_prototype'], dict): rule['trigger_prototypes']['trigger_prototype'] = [rule['trigger_prototypes']['trigger_prototype']]
                    for trigger_prot in rule['trigger_prototypes']['trigger_prototype']:
                        trigger_prot['comments'] = trigger_prot['description'] if 'description' in trigger_prot else ""
                        trigger_prot['description'] = trigger_prot['name']
                        del trigger_prot['name']
                        if 'url' in trigger_prot:
                            if '://' not in trigger_prot['url']: trigger_prot['url'] = "https://" + trigger_prot['url'] # add missed scheme if needed
                        if 'dependencies' in trigger_prot: # resolve dependencies
                            if isinstance(trigger_prot['dependencies']['dependency'], dict): trigger_prot['dependencies']['dependency'] = [trigger_prot['dependencies']['dependency']]
                            trigger_prot['dependencies'] = [{"triggerid": trigger2triggerid[(x['name'],host['name'])]} for x in trigger_prot['dependencies']['dependency']]
                        new_trigger_prot = zabbix.triggerprototype.create(trigger_prot)


                if 'graph_prototypes' in rule:
                    for item_prot in zabbix.itemprototype.get(output=["key_", "itemid"], hostids=new_hostid):
                        key2itemid[item_prot['key_']] = item_prot['itemid']

                    if isinstance(rule['graph_prototypes']['graph_prototype'], dict): rule['graph_prototypes']['graph_prototype'] = [rule['graph_prototypes']['graph_prototype']]
                    for graph_prot in rule['graph_prototypes']['graph_prototype']:
                        if isinstance(graph_prot['graph_items']['graph_item'], dict): graph_prot['graph_items']['graph_item'] = [graph_prot['graph_items']['graph_item']]
                        for gitem in graph_prot['graph_items']['graph_item']:
                            if 'item' in gitem:
                                gitem['itemid'] = key2itemid[gitem['item']['key']]
                                del gitem['item']
                        graph_prot['gitems'] = graph_prot['graph_items']['graph_item']
                        del graph_prot['graph_items']['graph_item']
                        new_graph_prot = zabbix.graphprototype.create(graph_prot)

        # TBD/TODO/FIXME:
        # - graphs
    except ZabbixAPIException as e:
        if 'already exists' in str(e):
            result = True
        else:
            logging.error(e)
            result = False
    return result

def import_template(zabbix, yml, group2groupid, template2templateid):
    "Import template from YAML. Return created object, None on error, True if object already exists"
    result = None
    try:
        new_template = yml['templates']['template']
        if new_template['template'] in template2templateid: return True # skip existing objects

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
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def import_usergroup(zabbix, yml, group2groupid, usergroup2usergroupid):
    "Import usergroup from YAML. Return created object , None on error, True if object already exists"
    if yml['name'] in usergroup2usergroupid: return True # skip existing objects

    result = None
    try:
        # set rights for new usergroup:
        if 'rights' in yml:
            if isinstance(yml['rights'], dict):
                rights = [{'id': yml['rights']['id'], 'permission': yml['rights']['permission']}]
            else:
                rights = []
                for r in yml['rights']:
                    rights.append({
                        "id": group2groupid[r['id']],
                        "permission": r['permission'],
                    })
        else:
            rights = []

        result = zabbix.usergroup.create(
            name=yml['name'],
            debug_mode=yml['debug_mode'] if 'debug_mode' in yml else 0,
            gui_access=yml['gui_access'] if 'gui_access' in yml else 0,
            users_status=yml['users_status'] if 'users_status' in yml else 0,
            rights=rights
        )
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def import_action(api_version, zabbix, yml, action2actionid, template2templateid, group2groupid, mediatype2mediatypeid, usergroup2usergroupid, user2userid, host2hostid, trigger2triggerid):
    "Import action from YAML. Return created object, None on error, True if object already exists"
    if yml['name'] in action2actionid: return True # skip existing objects

    result = None
    try:
        # resolve template/group/mediatype/usergroup names:
        for action_type in ('operations', 'acknowledgeOperations', 'recoveryOperations'):
            for op in yml[action_type]:
                if 'optemplate' in op:
                    for opt in op['optemplate']: opt['templateid'] = template2templateid[opt['templateid']]
                if 'opgroup' in op:
                    for opg in op['opgroup']: opg['groupid'] = group2groupid[opg['groupid']]
                if 'opmessage' in op:
                    op['opmessage']['mediatypeid'] = mediatype2mediatypeid[op['opmessage']['mediatypeid']]
                if 'opmessage_grp' in op:
                    for opmg in op['opmessage_grp']: opmg['usrgrpid'] = usergroup2usergroupid[opmg['usrgrpid']]
                if 'opmessage_usr' in op:
                    for opmg in op['opmessage_usr']: opmg['userid'] = user2userid[opmg['userid']]

        for condition in yml['filter']['conditions']:
            if condition['conditiontype'] == 0: # hostgroup
                condition['value'] = group2groupid[condition['value']]
            if condition['conditiontype'] == 1: # host
                condition['value'] = host2hostid[condition['value']]
            if condition['conditiontype'] == 13: # template
                condition['value'] = template2templateid[condition['value']]
            if condition['conditiontype'] == 2: # trigger
                condition['value'] = trigger2triggerid[(condition['value'],condition['value2'])]
                condition['value2'] = ''
            if condition['conditiontype'] == 16 and condition['operator'] == 7 and api_version >= parse_version("4"):# not in maintenance/suppression
                condition['operator'] = 11 # new in 4.x: see https://www.zabbix.com/documentation/4.2/manual/api/reference/action/object#action_filter_condition
            if condition['conditiontype'] == 16 and condition['operator'] == 4 and api_version >= parse_version("4"): # in maintenance/suppression
                condition['operator'] = 10 # new in 4.x: see https://www.zabbix.com/documentation/4.2/manual/api/reference/action/object#action_filter_condition

        result = zabbix.action.create(yml)
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def import_user(zabbix, yml, usergroup2usergroupid, user2userid, mediatype2mediatypeid):
    "Import user from YAML. Return created object, None on error, True if object already exists"
    if yml['alias'] in user2userid: return True # skip existing objects

    result = None
    try:
        groups = []
        for g in yml['usrgrps']:
            groups.append({"usrgrpid": usergroup2usergroupid[g['name']]})

        mediatypeid2mediatype = {'0': '__ALL__'} # key: mediatypeid, value: mediatype name
        for mt in yml['mediatypes']:
            mediatypeid2mediatype[mt['mediatypeid']] = mt['description']

        medias = []
        for m in yml['medias']:
            medias.append({
                "active": m['active'],
                "mediatypeid": mediatype2mediatypeid[mediatypeid2mediatype[m['mediatypeid']]],
                "period": m['period'],
                "sendto": m['sendto'],
                "severity": m['severity'] ,
            })

        result = zabbix.user.create({
            "alias": yml['alias'],
            "autologin": yml['autologin'] if 'autologin' in yml else 0,
            "autologout": yml['autologout'] if 'autologout' in yml else '15m',
            "lang": yml['lang'] if 'lang' in yml else 'en_GB',
            "name": yml['name'] if 'name' in yml else '',
            "surname": yml['surname'] if 'surname' in yml else '',
            "refresh": yml['refresh'] if 'refresh' in yml else '30s',
            "rows_per_page": yml['rows_per_page'] if 'rows_per_page' in yml else 50,
            "theme": yml['theme'] if 'theme' in yml else 'default',
            "type": yml['type'] if 'type' in yml else 1,
            "url": yml['url'] if 'url' in yml else '',
            "passwd": randompassword(), # YAML dump dont contains passwords/hashes
            "usrgrps": groups,
            "user_medias": medias,
        })
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def import_screen(zabbix, yml, screen2screenid, user2userid, usergroup2usergroupid):
    "Import screen from YAML. Return created object, None on error, True if object already exists"
    s = yml['screens']['screen']
    if s['name'] in screen2screenid: return True # skip existing objects

    result = None
    try:
        # resolve userids:
        resolved_users = []
        for u in s['users']:
            resolved_users.append({
                "permission": u['permission'],
                "userid": user2userid[u['userid']],
            })
        # resolve usrgrpids:
        resolved_grps = []
        for g in s['userGroups']:
            resolved_grps.append({
                "permission": g['permission'],
                "usrgrpid": usergroup2usergroupid[g['usrgrpid']],
            })

        result = zabbix.screen.create({
            "name": s['name'],
            "hsize": s['hsize'],
            "vsize": s['vsize'],
            "users": resolved_users,
            "userGroups": resolved_grps,
            "userid": user2userid[s['userid']],
            "private": s['private'],
            "screenitems": screenitems,
        })
    except ZabbixAPIException as e:
        if 'already exist' in str(e):
            result = True
        else:
            logging.exception(e)
    return result

def main(zabbix_, yaml_file, file_type, group_cache, template_cache, proxy_cache, host_cache, usergroup_cache, users_cache, mediatype_cache, screen_cache, action_cache, trigger_cache):
    "Main function: import YAML_FILE with type FILE_TYPE in ZABBIX_. Return None on error"
    api_version = parse_version(zabbix_.apiinfo.version())
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
            op_result = import_group(zabbix_, yml, group_cache)
        elif file_type == "template":
            op_result = import_template(zabbix_, yml, group_cache, template_cache)
        elif file_type == "proxy":
            op_result = import_proxy(zabbix_, yml, proxy_cache)
        elif file_type == "host":
            op_result = import_host(api_version, zabbix_, yml, group_cache, template_cache, proxy_cache, host_cache)
        elif file_type == "usergroup":
            op_result = import_usergroup(zabbix_, yml, group_cache, usergroup_cache)
        elif file_type == "user":
            op_result = import_user(zabbix_, yml, usergroup_cache, users_cache, mediatype_cache)
        # FIXME in future (too complex):
        # elif file_type == 'screen':
        #     op_result = import_screen(zabbix_, yml, screen_cache, users_cache, usergroup_cache)
        elif file_type == 'action':
            op_result = import_action(api_version, zabbix_, yml, action_cache, template_cache, group_cache, mediatype_cache, usergroup_cache, users_cache, host_cache, trigger_cache)
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
        group2groupid = {}
        template2templateid = {}
        proxy2proxyid = {}
        host2hostid = {}
        usergroup2usergroupid = {}
        user2userid = {}
        mediatype2mediatypeid = {}
        screen2screenid = {}
        action2actionid = {}
        trigger2triggerid = {}

        # load only needed caches:
        if args.type in ('autoguess', 'group', 'host', 'template', 'usergroup', 'action'):
            group2groupid = get_hostgroups_cache(zabbix_)
        if args.type in ('autoguess', 'host', 'template', 'action'):
            template2templateid = get_template_cache(zabbix_)
        if args.type in ('autoguess', 'proxy', 'host'):
            proxy2proxyid = get_proxy_cache(zabbix_)
        if args.type in ('autoguess', 'host', 'action'):
            host2hostid = get_hosts_cache(zabbix_)
        if args.type in ('autoguess', 'usergroup', 'action', 'user', 'screen'):
            usergroup2usergroupid = get_usergroup_cache(zabbix_)
        if args.type in ('autoguess', 'action', 'user', 'screen'):
            user2userid = get_users_cache(zabbix_)
        if args.type in ('autoguess', 'action', 'user'):
            mediatype2mediatypeid = get_mediatype_cache(zabbix_)
        if args.type in ('autoguess', 'screen'):
            screen2screenid = get_screen_cache(zabbix_)
        if args.type in ('autoguess', 'action'):
            action2actionid = get_action_cache(zabbix_)
        if args.type in ('autoguess', 'action'):
            trigger2triggerid = get_trigger_cache(zabbix_)

        for f in args.FILE:
            logging.info("Trying to load Zabbix object (type: {}) from: {}".format(args.type, os.path.abspath(f)))
            r = main(
                zabbix_=zabbix_,
                yaml_file=f,
                file_type=args.type,
                group_cache=group2groupid,
                template_cache=template2templateid,
                proxy_cache=proxy2proxyid,
                host_cache=host2hostid,
                usergroup_cache=usergroup2usergroupid,
                users_cache=user2userid,
                mediatype_cache=mediatype2mediatypeid,
                screen_cache=screen2screenid,
                action_cache=action2actionid,
                trigger_cache=trigger2triggerid,
            )
            if not r: result = False
    except Exception as e:
        result = False
        logging.exception(pformat(e))

    # Total success summary:
    if not result:
        logging.error("Some operations failed")
        sys.exit(1)
    logging.info("Done")
