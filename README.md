# Zabbix XML Review and Backup
Zabbix review and backup can create review mechanism to zabbix configuration

## Requirements
- `Python >=3.4`
- `make` (for windows install [cygwin](https://www.cygwin.com/))
- `git`

## Make review
1. Create backup and push to `develop` branch in configured git-repository which placed in directory `/path/to/git/with/zabbix-xml-file-only`. This repo must have `develop` branch and configured authentication
```bash
make ZBX_URL=https://zabbix.example.com ZBX_USER=user ZBX_PASSWORD='password' TARGET_DIR=/path/to/git/with/zabbix-xml-file-only
```
2. Only create backup in directory - use `make backup`
```bash
make backup ZBX_URL=https://zabbix.example.com ZBX_USER=user ZBX_PASSWORD='password' TARGET_DIR=/path/to/git/with/zabbix-xml-file-only
```
### Variables
- `ZBX_URL` - url to zabbix-server, `https://zabbix.example.com/` or `https://zabbix.example.com/zabbix`
- `ZBX_USER` - username with admin permission
- `ZBX_PASSWORD` - password
- `TARGET_DIR` - directory where xml\json will be placed. May be `git`-repository

## Supported data
XML data:
- hosts
- templates
- screen

JSON:
- mediatypes
- actions
