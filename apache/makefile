REQ_FILE  = /var/django/generated/relad_request
DONE_FILE = /var/django/generated/request_done

CC          = /usr/bin/touch
SERVICE     = /usr/sbin/service
SERVICE_CMD = reload
INSTANCE    = apache2

${DONE_FILE}:
	${SERVICE} ${INSTANCE} ${SERVICE_CMD}
	${CC} ${DONE_FILE}

all: ${DONE_FILE}
