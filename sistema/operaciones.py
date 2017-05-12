# -*- coding: utf-8 -*-
import subprocess
import re
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

def analyzeNMAP(result):
    lines = result.split("\n")
    for line in lines:
        if ("/tcp" in line) or ("/udp" in line):
            if ("open" in line) and not ("filtered" in line):
                # Puerto Abierto, obtenemos servicio
                # Dejamos la línea sólo con espacios
                while "  " in line:
                    line = line.replace("  ", " ");
                print line
            elif ("closed" in line) and not ("filtered" in line):
                # Puerto Cerrado
                print "Cerrado"
            elif ("open" in line) and ("filtered" in line):
                # Puerto open|filtered
                print "open|filtered"
            elif ("closed" in line) and ("filtered" in line):
                # Puerto closed|filtered
                print "closed|filtered"
            elif ("unfiltered" in line):
                # Puerto unfiltered
                print "unfiltered"
        #if ()
