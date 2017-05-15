#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Imports del sistema
import os
import sys
import subprocess
import multiprocessing
import logging
import time
# Imports de paquetes propios
import sistema.operaciones as oper
import classes.analyzedIP as aip

# Variables  globales
analyzedIPs = {} # Diccionario con todas las IPs que se analizan

# Comprobación de parámetros
print ("xauditor alpha 0.1")
if len (sys.argv) < 2:
    print ("<ERROR>: Hay que introducir una dirección IP al menos")
    sys.exit()

# Función para multiproceso
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

# Método para crear el log de xauditor
def createLogger(mainPath):
    # Creamos el logger
    #logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("xauditor")
    # Creamos formato de log
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Establecemos el nivel
    logger.setLevel(logging.DEBUG)
    # Creamos console handle para mostrar log en la consola
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)

    # Creamos file handler para guardar el log en un fichero
    fh = logging.FileHandler(mainPath + '/xauditor@%s.log' % time.strftime("%H_%M_%S"))
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)

    # Añadir al logger los handlers para que se encargue de generar los logs
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

# Comienzo del programa
if __name__=='__main__':
    # Recogemos IPs de los argumentos
    targets = sys.argv
    # Quitamos el primer objeto porque es el nombre del programa
    targets.pop(0)

    # Creamos directorio de la aplicación si es necesario
    mainPath = "%s/xauditor/%s" % (os.environ['HOME'],time.strftime("%d_%m_%Y"))
    if not os.path.exists(mainPath):
        print ("Creando directorio para aplicación xauditor")
        print("Directorio Aplicación: %s" % (mainPath))
        os.makedirs(mainPath)

    # Creamos el logger de la aplicación
    logger = createLogger(mainPath)

    # Recorremos cada IP obtenida y vamos ejecutando análisis de reco
    for scanip in targets:
        if oper.validIP(scanip) is not None:
            # Creamos directorios para la IP
            dirs = os.listdir(mainPath)
            ipPath = mainPath + "/%s" % (scanip)
            if not scanip in dirs:
                logger.info ("Creando directorio para la dirección IP")
                logger.debug("Directorio IP: %s" % (ipPath))
                os.makedirs(ipPath)
            # Creamos nuevo objeto analyzedIP
            ip = aip.AnalizedIP(scanip,ipPath)

            # Proceso para realizar escaneos NMAP
            p = multiprocessing.Process(target=ip.analyze, args=())
            p.start()
        else:
            logger.error ("IP %s tiene un formato incorrecto",scanip)
