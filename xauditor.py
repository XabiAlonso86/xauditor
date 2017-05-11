#!/usr/bin/env python
# Imports del sistema
import os
import sys
import subprocess
# Imports de paquetes propios
import sistema.operaciones as sistema
from classes.auditedip import AuditedIP

print ("xauditor alpha 0.1")
if len (sys.argv) < 2:
    print ("Hay que usar un argumento")
    sys.exit()

# Comienzo del programa
if __name__=='__main__':

    # Variables
    hilos = []
    # Recogemos IPs
    targets = sys.argv
    # Quitamos el primer objeto porque es el nombre del programa
    targets.pop(0)

    # Establecemos MainPath y creamos si es necesario
    mainPath = "%s/xauditor/" % (os.environ['HOME'])
    if not os.path.exists(mainPath):
        sistema.createMainPath(mainPath)
    # Recorremos cada IP obtenida y vamos ejecutando análisis
    for scanip in targets:
        ip = AuditedIP(scanip, mainPath)
        ip.setName('Thread_' + scanip)
        hilos.append(ip)

    for hilo in hilos:
        hilo.start()
    for hilo in hilos:
        hilo.join()
