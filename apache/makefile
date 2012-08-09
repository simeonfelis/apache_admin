REQ_FILE  = /var/django/generated/reload_request
DONE_FILE = /var/django/generated/request_done

CC          = /usr/bin/touch

WGET        = /usr/bin/wget
WGET_OPT    = --no-check-certificate --quiet -O -
USER        = maintenance
PASSWD      = lohg2GaiheeM
URL         = https://${USER}:${PASSWD}@localhost/django/maintenance

SERVICE     = /usr/sbin/service
SERVICE_CMD = reload
INSTANCE    = apache2

all: ${DONE_FILE}

${DONE_FILE}: ${REQ_FILE}
	${SERVICE} ${INSTANCE} ${SERVICE_CMD} > /dev/null
	${WGET} ${WGET_OPT} ${URL} > /dev/null
	${CC} ${DONE_FILE}
