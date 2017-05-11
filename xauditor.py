#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Imports del sistema
import os
import sys
import subprocess
# Imports de paquetes propios
import sistema.operaciones as sistema
from classes.auditedip import AuditedIP

print ("xauditor alpha 0.1")
if len (sys.argv) < 2:
    print ("<ERROR>: Hay que introducir una dirección IP al menos")
    sys.exit()

# Comienzo del programa
if __name__=='__main__':
    try:
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
            try:
                ip = AuditedIP(scanip, mainPath)
                ip.setName('Thread_' + scanip)
                hilos.append(ip)
            # Excepción en caso de IP mal formateada
            except ValueError:
                print ("<ERROR>: IP " + scanip + " tiene un formato incorrecto")

        # Corremos Hilos y esperamos a que terminen
        for hilo in hilos:
            hilo.start()
        for hilo in hilos:
            hilo.join()
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        print "<ERROR>: Interrumpido por el usuario"
