#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Imports del sistema
import os
import sys
import subprocess
import multiprocessing as mp
import logging
import time
# Imports de paquetes propios
import sistema.operaciones as oper
import classes.scaner as scn


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
    p = mp.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

# Método para crear el log de xauditor
def createLogger(mainPath):
    # Creamos el logger
    #logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("xauditor")
    # Creamos formato de log consola
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    # Establecemos el nivel
    logger.setLevel(logging.DEBUG)
    # Creamos console handle para mostrar log en la consola
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)

    # Creamos Formatter para file handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Creamos file handler para guardar el log en un fichero
    fh = logging.FileHandler(mainPath + '/xauditor@%s.log' % time.strftime("%H_%M_%S"))
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)

    # Añadir al logger los handlers para que se encargue de generar los logs
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def analyzeIP(ip,folder):
    # Variables para guardar procesos creados para la ip
    jobs = []
    # Manager para compartir diccionarios en los procesos
    manager = mp.Manager()
    servicios = manager.dict()
    serviciosUDP = manager.dict()
    # Creamos procesos escaneo NMAP
    p = mp.Process(target=scn.nmapScan,name="nmapScan_" + ip, args=(scanip,ipPath,servicios))
    jobs.append(p)
    p.start()
    p = mp.Process(target=scn.nmapScan,name="nmapUdpScan_" + ip, args=(scanip,ipPath,serviciosUDP))
    jobs.append(p)
    p.start()
    contJobs += 1
    # UnicornScan (sólo guardamos resultado)
    p = mp.Process(target=scn.unicornScan,name="unicornScan_" + ip, args=(scanip,ipPath))
    jobs.append(p)
    p.start()
    contJobs += 1
    # Entramos en bucle hasta que se completen todos los procesos
    # Es posible que los resultados de un proceso impliquen la creación de otro
    print ("Procesos: %s" % (len(jobs)))
    timerElapsed = 0
    while len(jobs) > 0:
        for job in jobs:
            job.join(5)
            timerElapsed += 5
            if not job.exitcode is None:
                logger.info("Proceso %s ha acabado!" % (job.name))
                jobFinished = job.name
                jobs.remove(job)
                # Miramos qué proceso ha terminado y si hay que crear alguno más
                if "nmapScan" in jobFinished:
                    checkJobIPFinished(jobFinished,jobs,ip,ipPath,servicios)
                elif "nmapUdpScan" in jobFinished:
                    checkJobIPFinished(jobFinished,jobs,ip,ipPath,serviciosUDP)
                else:
                    checkJobIPFinished(jobFinished,jobs,ip,ipPath)
                logger.info("Quedan %s" % (len(jobs)))
            else:
                # Cada 30 Segundos mostramos lo que lleva la tarea
                if (timerElapsed % 30) == 0:
                    logger.info("analyzeIP de IP %s lleva %s minutos" % (ip,time.strftime("%M:%S", time.gmtime(timerElapsed))))
                    line = ""
                    for job in jobs:
                        line += job.name + " "
                    logger.info("Procesos pendientes: %s" % (line))

    
# Método para comprobar que proceso de análisis de IP ha terminado
# * args recibirá servicios ocasionalmente por eso no se pasa siempre
def checkJobIPFinished(nombre,listaJobs,ip,folder,*args):

    logger.debug("Entro checkJobIPFinished (%s)." % (nombre))
    if "nmapScan" in nombre or "nmapUdpScan" in nombre:
        # Analizamos los servicios encontrados        
        servicios = args[0]    
        # Lo primero es ver si tenemos más de un serivio (servicio OS siempre está)
        if len(servicios) == 1:
            logger.info("No se han encontrado servicios para la IP %s. Revise los análisis de NMAP para mayor información" % (ip))
        else:
            for nombre, servicio in servicios.items():
                # Servicio HTTP
                if (nombre == "http") or (nombre == "http-proxy") or (nombre == "http-alt") or (nombre == "http?"):
                    for puerto in servicio.puertos:
                        # Lanzamos proceso para analizar http
                        logger.info("Encontrado servicio http para ip %s en puerto %s" % (ip,puerto))
                        # Creamos proceso y lo añadimos a la lista
                        p = mp.Process(target=httpenum,name="httpenum_" + ip, args=(ip,puerto,folder))
                        listaJobs.append(p)
                        logger.info("Añadido nuevo proceso a la lista de la IP %s. Ahora hay %s" % (ip,len(listaJobs)))
                        # Iniciamos el proceso
                        p.start()
                # Servicio HTTPS
                elif (nombre == "ssl/http") or (nombre == "https") or (nombre == "https?"):
                    for puerto in servicio.puertos:
                        # Lanzamos proceso para analizar https
                        logger.info("Encontrado servicio https para ip %s en puerto %s" % (ip,puerto))
                        # Creamos proceso y lo añadimos a la lista
                        p = mp.Process(target=httpsenum,name="httpsenum_" + ip, args=(ip,puerto,folder))
                        listaJobs.append(p)
                        logger.info("Añadido nuevo proceso a la lista de la IP %s. Ahora hay %s" % (ip,len(listaJobs)))
                        # Iniciamos el proceso
                        p.start()

    logger.debug("Fin checkJobIPFinished.")
    return


# Método para lanzar Nikto, dirb, curl y script de NMAP con servicio HTTP
def httpenum(ip,puerto,folder):
    # Variables para guardar procesos creados para la ip
    jobs = []
    folderHttp =  folder + "/http"
    logger.info ("Iniciando enumeración HTTP para la IP %s:%s" % (ip,puerto))
    # Creamos directorios de las carpetas
    if not os.path.exists(folderHttp):
        logger.info("Creamos directorio http")
        os.makedirs(folderHttp)
    # Creamos procesos
    # dirbScan
    p = mp.Process(target=scn.dirbScan,name="dirbScan_" + ip, args=(ip,puerto,"http",folderHttp))
    jobs.append(p)
    p.start()
    # nikto
    p = mp.Process(target=scn.niktoScan,name="niktoScan_" + ip, args=(ip,puerto,"http",folderHttp))
    jobs.append(p)
    p.start()
    scn.curlScan(ip,puerto,folderHttp)
    p = mp.Process(target=scn.nmapScriptsLauncher,name="nmapScriptsLauncher_" + ip, args=(ip,puerto,folderHttp,"HTTP"))
    jobs.append(p)
    p.start()
    timerElapsed = 0
    while len(jobs) > 0:
        for job in jobs:
            job.join(5)
            timerElapsed += 5
            if not job.exitcode is None:
                logger.info("Proceso httpenum de IP %s %s ha acabado!" % (ip, job.name))
                jobs.remove(job)
                logger.info("%s proceso/s restante/s httpenum de IP %s" % (len(jobs),ip))
            else:
                # Cada 30 Segundos mostramos lo que lleva la tarea
                if (timerElapsed % 30) == 0:
                    logger.info("httpenum de IP %s lleva %s minutos" % (ip,time.strftime("%M:%S", time.gmtime(timerElapsed))))
                    line = ""
                    for job in jobs:
                        line += job.name + " "
                    logger.info("Procesos pendientes: %s" % (line))

    logger.debug("Fin enumeración HTTP para la IP %s:%s" % (ip,puerto))
    return

# Método para lanzar Nikto, dirb, curl y script de NMAP con servicio HTTPS
def httpsenum(ip,puerto,folder):
    # Variables para guardar procesos creados para la ip
    jobs = []
    folderHttps =  folder + "/https"
    logger.info ("Iniciando enumeración HTTPS para la IP %s:%s" % (ip,puerto))
    # Creamos directorios de las carpetas
    if not os.path.exists(folderHttps):
        logger.info("Creamos directorio https")
        os.makedirs(folderHttps)
    # dirbScan
    p = Popenmp.Process(target=scn.dirbScan,name="dirbScanHTTPS_" + ip, args=(ip,puerto,"https",folderHttps))
    jobs.append(p)
    p.start()
    # nikto
    p = mp.Process(target=scn.niktoScan,name="niktoScanHTTPS_" + ip, args=(ip,puerto,"https",folderHttps))
    jobs.append(p)
    p.start()
    # sslScan
    p = mp.Process(target=scn.sslScan,name="sslScan_" + ip, args=(ip,puerto,folderHttps))
    jobs.append(p)
    p.start()
    #nmapHTTP_process = multiprocessing.Process(target=nmapScriptsLauncher, args=(ip,puerto,folderHttps,"HTTP"))
    #nmapHTTP_process.start()
    timerElapsed = 0
    while len(jobs) > 0:
        for job in jobs:
            job.join(5)
            timerElapsed += 5
            if not job.exitcode is None:
                logger.info("Proceso httpsenum de IP %s %s ha acabado!" % (ip, job.name))
                jobs.remove(job)
                logger.info("Quedan %s procesos httpsenum de IP %s" % (len(jobs),ip))
            else:
                # Cada 30 Segundos mostramos lo que lleva la tarea
                if (timerElapsed % 30) == 0:
                    logger.info("httpsenum de IP %s lleva %s minutos" % (ip,time.strftime("%M:%S", time.gmtime(timerElapsed))))
                    line = ""
                    for job in jobs:
                        line += job.name + " "
                    logger.info("Procesos pendientes: %s" % (line))

    logger.debug("Fin enumeración HTTPS para la IP %s:%s" % (ip,puerto))
    return

# Comienzo del programa
if __name__=='__main__':

    listaIPs = []
    # Recogemos IPs de los argumentos
    targets = sys.argv
    # Quitamos el primer objeto porque es el nombre del programa
    targets.pop(0)

    # Creamos directorio de la aplicación si es necesario
    mainPath = "%s/xauditor/" % (os.environ['HOME'])
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
            ipPath = oper.createIPPath(mainPath,scanip)
            # Comenzamos proceso para analizar la IP
            p = mp.Process(target=analyzeIP,name="analyzeIP_" + scanip, args=(scanip,ipPath))
            listaIPs.append(p)
            p.start()
            logger.debug("Fin iteración para ip %s." % (scanip))
        else:
            logger.error ("IP %s tiene un formato incorrecto",scanip)
    
    os.system('stty sane')


