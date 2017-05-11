# -*- coding: utf-8 -*-
import subprocess
def createMainPath(mainPath):
    print ("<INFO>: Creando directorio de la aplicación en " + mainPath)
    subprocess.check_output("mkdir " + mainPath, shell=True)

def createPath(mainPath, ip_address):
    print ("<INFO>: Creando directorios para IP " + ip_address)
    subprocess.check_output("mkdir " + mainPath + "/" + ip_address, shell=True)
