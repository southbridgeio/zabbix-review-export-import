.PHONY: prepare env
push: backup
	git add .
	git commit -m':robot: Autobackup'
	git push origin develop

env:
    ifndef ZBX_URL
        $(error ZBX_URL is undefined)
    endif
    ifndef ZBX_USER
        $(error ZBX_USER is undefined)
    endif
    ifndef ZBX_PASSWORD
        $(error ZBX_PASSWORD is undefined)
    endif

prepare:
	python -mpip install -r ./requirements.txt

backup: prepare
	python ./backup.py --zabbix-url $(ZBX_URL) --zabbix-username $(ZBX_USER) --zabbix-password '$(ZBX_PASSWORD)'
