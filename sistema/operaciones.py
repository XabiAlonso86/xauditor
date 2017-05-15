# -*- coding: utf-8 -*-
import subprocess
import re
import logging
# Paquetes locales
import classes.servicio as srv

module_logger = logging.getLogger('xauditor').getChild('operaciones')

# Método para crear directorio de xauditor
def createMainPath(mainPath):
    module_logger.info("Creando directorio de la aplicación en %s",mainPath)
    subprocess.check_output("mkdir " + mainPath, shell=True)

# Método para crear directorios para el análisis de una Dirección IP
def createPath(mainPath, ip_address):
    module_logger.info("Creando directorios para IP %s",ip_address)
    subprocess.check_output("mkdir " + mainPath + "/" + ip_address, shell=True)

# Método para validar una IP
def validIP(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)
