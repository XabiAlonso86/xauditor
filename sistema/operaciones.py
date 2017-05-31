# -*- coding: utf-8 -*-
import subprocess
import re
import logging
import os
import time
# Paquetes locales
import classes.servicio as srv

logger = logging.getLogger('xauditor').getChild('operaciones')

# Método para validar una IP
def validIP(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)

# Método para crear directorios de una ip a analizar
def createIPPath(path,ip):
    dirs = os.listdir(path)
    ipPath = path + "/%s" % (ip)
    if not ip in dirs:
        logger.info ("Creando directorio para la dirección IP")
        logger.debug("Directorio IP: %s" % (ipPath))
        os.makedirs(ipPath)
    # Creamos directorio fecha
    dirs = os.listdir(ipPath)
    ipPath = ipPath + "/%s" % time.strftime("%d_%m_%Y")
    if not time.strftime("%d_%m_%Y") in dirs:
        logger.info ("Creando directorio fecha para la dirección IP")
        logger.debug("Directorio Fecha: %s" % (ipPath))
        os.makedirs(ipPath)

    return ipPath

def createFolder(path):
    # Creamos directorios de las carpetas
    if not os.path.exists(path):
        logger.debug("Creamos directorio %s" % (path))
        os.makedirs(path)
    return