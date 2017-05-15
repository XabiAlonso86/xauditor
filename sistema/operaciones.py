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

# Método que analiza la línea NMAP para un puerto
def processPortLine(line, services):
    estado = ''
    # Dejamos la línea sólo con espacios
    while "  " in line:
        line = line.replace("  ", " ")
    lineSplit = line.split(" ")
    # Nombre del servicio
    nombre = lineSplit[2]
    # Puerto
    puerto = lineSplit[0].split("/")[0]
    # Version
    version = ' '.join(lineSplit[3:])
    # Estado
    estado = lineSplit[1]
    # Si existe el servicio añadimos una opción nueva, si no lo creamos
    if nombre in services:
        services[nombre].puertos.append(lineSplit[0].split("/")[0])
        services[nombre].versiones.append(' '.join(lineSplit[3:]))
        services[nombre].estados.append(estado)
    else:
        servicio = srv.Servicio(nombre)
        servicio.puertos.append(puerto)
        servicio.versiones.append(version)
        servicio.estados.append(estado)
        services[nombre] = servicio

# Método para analizar la línea de SO de NMAP cuando encuentra 100%
def processOSLine(line,services):

    if ("JUST GUESSING" in line):
        # No sabemos que OS es a ciencia cierta
        nombre = "Desconocido"
    elif ("Windows" in line) and not ("Linux" in line):
        # Es un Windows
        nombre = "Windows"
    elif ("Linux" in line) and not ("Windows" in line):
        # Es un Linux
        nombre = "Linux"

    servicio = srv.Servicio(nombre)
    servicio.puertos.append("0")
    servicio.versiones.append("0")
    servicio.estados.append("0")
    services[nombre] = servicio

# Método que analiza los resultados línea a línea de un test NMAP
def analyzeNMAP(result):

    module_logger.info ("Log Info 2")
    module_logger.debug ("Log Debug 2")
    module_logger.error ("Log Error 2")

    # Creamos diccionario de servicios
    services = {}
    lines = result.split('\n')
    for line in lines:
        if ("/tcp" in line) or ("/udp" in line):
            processPortLine(line,services)
        elif ("Running" in line):
            processOSLine(line,services)

    # Devolvemos los servicios
    return services
