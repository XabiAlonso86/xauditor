# -*- coding: utf-8 -*-
import subprocess
import re
# Paquetes locales
import classes.servicio as srv

# Método para crear directorio de xauditor
def createMainPath(mainPath):
    print ("<INFO>: Creando directorio de la aplicación en " + mainPath)
    subprocess.check_output("mkdir " + mainPath, shell=True)

# Método para crear directorios para el análisis de una Dirección IP
def createPath(mainPath, ip_address):
    print ("<INFO>: Creando directorios para IP " + ip_address)
    subprocess.check_output("mkdir " + mainPath + ip_address, shell=True)

# Método para validar una IP
def validIP(ip):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",ip)

# Método que analiza la línea NMPA para un puerto
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

# Método que analiza los resultados línea a línea de un test NMAP
def analyzeNMAP(result):
    # Creamos diccionario de servicios
    services = {}
    lines = result.split("\n")
    for line in lines:
        if ("/tcp" in line) or ("/udp" in line):
            processPortLine(line,services)

    for nombre, servicio in services.items():
        print nombre
    print len(services)
    # Devolvemos lista de servicios
    return services
