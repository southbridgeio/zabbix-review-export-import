# Zabbix XML Review and Backup


## Requirements
- `Python >=3.4`
- `make` (for windows install [cygwin](https://www.cygwin.com/))
- `git`

## Make review
1. Create backup and push to `develop` branch in configured git-repository which placed
```bash
make ZBX_URL=https://zabbix.example.com ZBX_USER=user ZBX_PASSWORD='password' TARGET_DIR=/path/to/git/with/zabbix-xml-file-only
```

## Supported data
XML data:
- hosts
- templates
- screen

JSON:
- mediatypes
- actions
