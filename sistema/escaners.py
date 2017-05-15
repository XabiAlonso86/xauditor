# -*- coding: utf-8 -*-
import logging
import time
import subprocess
from multiprocessing import Queue
# Paquetes locales
import classes.servicio as srv

# A falta de configuración por fichero...
logger = logging.getLogger('xauditor').getChild('escaners')
