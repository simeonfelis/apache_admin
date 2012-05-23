REQ_FILE  = /var/django/generated/reload_request
DONE_FILE = /var/django/generated/request_done

CC          = /usr/bin/touch
SERVICE     = /usr/sbin/service
SERVICE_CMD = reload
INSTANCE    = apache2

all: ${DONE_FILE}

${DONE_FILE}: ${REQ_FILE}
	${SERVICE} ${INSTANCE} ${SERVICE_CMD}
	${CC} ${DONE_FILE}

