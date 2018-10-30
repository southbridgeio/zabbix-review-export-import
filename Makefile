.PHONY: zbx_env gitlab_env
ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

ifndef ZBX_URL
	$(error ZBX_USER is undefined)
endif
ifndef ZBX_USER
	$(error ZBX_USER is undefined)
endif
ifndef ZBX_PASSWORD
	$(error ZBX_PASSWORD is undefined)
endif
ifndef TARGET_DIR
	$(error TARGET_DIR is undefined)
endif

push: pull backup
	set -e; \
	cd ${TARGET_DIR}; \
	git add .; \
	d=$(date +%Y-%m-%d); \
	git commit -m':robot: Autobackup $d'; \
	git push origin develop

pull: zbx_env
	cd ${TARGET_DIR}; \
	git checkout -b develop origin/develop || git checkout develop; \
	git pull; \
	rm -rf *

zbx_env:

prepare:
	python -mpip install -r ${ROOT_DIR}/requirements.txt

backup: prepare zbx_env
	cd ${TARGET_DIR}; \
	python ${ROOT_DIR}/backup.py --zabbix-url $(ZBX_URL) --zabbix-username $(ZBX_USER) --zabbix-password '$(ZBX_PASSWORD)'
