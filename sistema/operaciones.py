# -*- coding: utf-8 -*-
import subprocess
import re
import logging
# Paquetes locales
import classes.servicio as srv

module_logger = logging.getLogger('xauditor').getChild('operaciones')

# Método para validar una IP
def validIP(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
