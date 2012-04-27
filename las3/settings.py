# settings.py

import socket

if socket.gethostname() == 'rfhete470':
    from settings_production import *
elif socket.gethostname() == 'pandora':
    from settings_dev_simeon import *
elif socket.gethostname() == 'arpa':
    from settings_dev_simeon import *


