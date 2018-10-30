# Zabbix XML Review and Backup


## Requirements
- `Python >=3.4`
- `make` (for windows install [cygwin](https://www.cygwin.com/))
- `git`

## Make review
```bash
make ZBX_URL=https://zabbix.example.com ZBX_USER=user ZBX_PASSWORD='password'
```

## Supported data
XML data:
- hosts
- templates
- screen

JSON:
- mediatypes
- actions
