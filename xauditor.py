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

# Función de escaneo NMAP
def nmapScan(ip_address, mainPath):
    nmapCmd = "sudo nmap -sV -O %s -oN '%s/%s/%s.nmap'" % (ip_address,mainPath,ip_address,ip_address)
    logger.info("Escaneo nmap de versiones (%s) sobre %s",nmapCmd,ip_address)
    try:
        results = subprocess.check_output(nmapCmd, shell=True)
        # Analizamos resultados y obtenemos lista de servicios disponibles
        services = oper.analyzeNMAP(results)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.error("Escaneo TCP Version sobre %s interrumpido por el usuario.",ip_address)
    #print (results)

    # Lanzamos UDPScan
    #p = multiprocessing.Process(target=udpScan, args=(ip_address, mainPath))
    #p.start()

# Función de escaneo NMAP a los puertos UDP
def udpScan(ip_address, mainPath):
    logger.info("Escaneo UDP sobre %s",ip_address)
    nmapCmd = "sudo nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/%s/udp_%s.nmap' %s"  % (mainPath,ip_address,ip_address,ip_address)
    logger.info("Escaneo nmap UDP (%s) sobre %s",nmapCmd,ip_address)
    try:
        udpscan_results = subprocess.check_output(nmapCmd, shell=True)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.error("Escaneo UDP sobre %s interrumpido por el usuario.",ip_address)

    logger.info("Terminado escaneo UDP para %s",ip_address)
    print udpscan_results
    logger.info("Escaneo UDP unicornscan sobre %s",ip_address)
    unicornCmd = "unicornscan -mU -v -I %s > '%s/%s/unicordn_udp_%s.txt'" % (ip_address,mainPath, ip_address, ip_address)
    #unicornscan_results = subprocess.check_output(unicornCmd, shell=True)
    logger.info("Unicornscan finalizado sobre %s",ip_address)


# Comienzo del programa
if __name__=='__main__':
    # Recogemos IPs de los argumentos
    targets = sys.argv
    # Quitamos el primer objeto porque es el nombre del programa
    targets.pop(0)

    time.strftime("%d_%m_%Y")

    # Creamos directorio de la aplicación si es necesario
    mainPath = "%s/xauditor/%s" % (os.environ['HOME'],time.strftime("%d_%m_%Y"))
    if not os.path.exists(mainPath):
        oper.createMainPath(mainPath)

    # Creamos el logger
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("xauditor")

    # Creamos file handler para guardar el log en un fichero
    fh = logging.FileHandler(mainPath + '/xauditor@%s.log' % time.strftime("%H_%M_%S"))
    fh.setLevel(logging.DEBUG)
    # Creamos console handle para mostrar log en la consola
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    # Creamos formato de log y lo añadimos a los handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # Añadir al logger los handlers para que se encargue de generar los logs
    logger.addHandler(fh)
    logger.addHandler(ch)

    # Recorremos cada IP obtenida y vamos ejecutando análisis de reco
    for scanip in targets:
        if oper.validIP(scanip) is not None:
            # Creamos directorios para la IP
            dirs = os.listdir(mainPath)
            if not scanip in dirs:
                oper.createPath(mainPath, scanip)
            # Proceso para realizar escaneos NMAP
            p = multiprocessing.Process(target=nmapScan, args=(scanip,mainPath))
            p.start()
        else:
            logger.error ("<ERROR>: IP %s tiene un formato incorrecto",scanip)
