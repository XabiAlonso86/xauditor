#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Imports del sistema
import os
import sys
import subprocess
import multiprocessing
# Imports de paquetes propios
import sistema.operaciones as oper
from classes.auditedip import AuditedIP

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
    nmapCmd = "sudo nmap -sV -O %s -oN '%s%s/%s_grep.nmap'" % (ip_address,mainPath,ip_address,ip_address)
    print "<INFO>: Escaneo nmap de versiones (" + nmapCmd + ") sobre " + ip_address
    try:
        results = subprocess.check_output(nmapCmd, shell=True)
        # Analizamos resultados
        oper.analyzeNMAP(results)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        print "<ERROR>: Escaneo TCP Version sobre " + ip_address + " interrumpido por el usuario."
    #print (results)

    # Lanzamos UDPScan (De momento no, que no tiene mucho sentido)
    #p = multiprocessing.Process(target=udpScan, args=(ip_address, mainPath))
    #p.start()

# Función de escaneo NMAP a los puertos UDP
def udpScan(ip_address, mainPath):
    print "<INFO>: Escaneo UDP sobre " + ip_address
    nmapCmd = "sudo nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s%s/udp_%s.nmap' %s"  % (mainPath,ip_address,ip_address,ip_address)
    print "<INFO>: Escaneo UDP (" + nmapCmd + ") sobre " + ip_address
    try:
        udpscan_results = subprocess.check_output(nmapCmd, shell=True)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        print "<ERROR>: Escaneo UDP sobre " + ip_address + " interrumpido por el usuario."

    print "<INFO>: Terminado escaneo UDP para " + ip_address
    print udpscan_results
    print "<INFO>: Escaneo UDP unicornscan sobre " + ip_address
    unicornCmd = "unicornscan -mU -v -I %s > '%s/%s/unicordn_udp_%s.txt'" % (ip_address,mainPath, ip_address, ip_address)
    #unicornscan_results = subprocess.check_output(unicornCmd, shell=True)
    print "<INFO>: unicornscan finalizado sobre " + ip_address


# Comienzo del programa
if __name__=='__main__':
    # Recogemos IPs de los argumentos
    targets = sys.argv
    # Quitamos el primer objeto porque es el nombre del programa
    targets.pop(0)

    # Creamos directorio de la aplicación si es necesario
    mainPath = "%s/xauditor/" % (os.environ['HOME'])
    if not os.path.exists(mainPath):
        oper.createMainPath(mainPath)
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
            print ("<ERROR>: IP " + scanip + " tiene un formato incorrecto")

        # Corremos Hilos y esperamos a que terminen
        #for hilo in hilos:
        #    hilo.start()
        #for hilo in hilos:
        #    hilo.join()
