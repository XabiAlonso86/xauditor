# -*- coding: utf-8 -*-
import subprocess
import logging
import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor
# Imports paquetes locales
import classes.servicio as srv
# A falta de configuración por fichero...
logger = logging.getLogger('xauditor').getChild('analyzedIP')

# Variables Módulo
jobs = []

class AnalizedIP:
    # Constructor de la clase
    def __init__(self,ip,folder):
        self.ip = ip
        self.folder = folder
        self.servicios = {}
        self.serviciosUDP = {}

    # Método para analizar una IP
    def analyze(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            resultNmapScan = executor.submit(nmapScan, self.ip,self.folder)
            resultUDPScan= executor.submit(udpScan, self.ip,self.folder)

        self.servicios = resultNmapScan.result()
        self.serviciosUDP = resultUDPScan.result()

        # Obtenidos los servicios de la dirección IP hay que analizarlos
        # y ver si se pueden lanzar nuevos comandos
        print ("Servicios dirección %s: %s" % (self.ip, len(self.servicios)))
        print ("Servicios UDP dirección %s: %s" % (self.ip, len(self.serviciosUDP)))
        self.analyzeServices()

    def analyzeServices(self):
        # Lo primero es ver si tenemos más de un serivio (servicio OS siempre está)
        if len(self.servicios) == 1:
            logger.info("No se han encontrado servicios para la IP %s. Revise el análisis de NMAP o comience a investigar por su cuenta." % (self.ip))
        else:
            for nombre, servicio in self.servicios.items():
                # Servicio HTTP
                if (nombre == "http") or (nombre == "http-proxy") or (nombre == "http-alt") or (nombre == "http?"):
                    for port in servicio.puertos:
                        print ("Encontrado servicio http para ip %s en puerto %s" % (self.ip,port))

        if len(self.serviciosUDP) == 1:
            logger.info("No se han encontrado servicios UDP para la IP %s. Revise el análisis de NMAP o comience a investigar por su cuenta." % (self.ip))

        # Primero miramos los servicios que no son UDP




# Función para multiproceso
def multProc(targetin,ip,folder):
    p = multiprocessing.Process(target=targetin, args=(ip,folder))
    jobs.append(p)
    return

# Función de escaneo NMAP
def nmapScan(ip,folder):
    servicios = {}
    nmapCmd = "sudo nmap -sV -O %s -oN '%s/%s@%s.nmap'" % (ip,folder,ip,time.strftime("%H_%M_%S"))
    logger.info("Escaneo nmap de versiones sobre %s",ip)
    logger.debug("Comando nmapScan: %s",nmapCmd)
    try:
        results = subprocess.getoutput(nmapCmd)
        # Analizamos resultados y obtenemos lista de servicios disponibles
        return analyzeNMAPResult(results)
        #for nombre, servicio in servicios.items():
        #    print (nombre)
        #print (len(servicios))
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.exception("Escaneo TCP Version sobre %s interrumpido por el usuario.",ip)
    #print (results)

    # Lanzamos UDPScan
    #p = multiprocessing.Process(target=udpScan, args=(ip_address, mainPath))
    #p.start()


# Función de escaneo NMAP a los puertos UDP
def udpScan(ip,folder):
    servicios = {}
    nmapCmd = "sudo nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/udp_%s@%s.nmap' %s"  % (folder,ip,time.strftime("%H_%M_%S"),ip)
    logger.info("Escaneo nmap UDP sobre %s",ip)
    logger.debug("Comando udpScan: %s",nmapCmd)
    try:
        servicio = srv.Servicio("hola")
        servicio.puertos.append("0")
        servicio.versiones.append("0")
        servicio.estados.append("0")
        servicios["hola"] = servicio
        return servicios
        #udpscan_results = subprocess.getoutput(nmapCmd)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.error("Escaneo UDP sobre %s interrumpido por el usuario.",ip)

    #logger.info("Terminado escaneo UDP para %s",ip.address)
    #print (udpscan_results)
    #logger.info("Escaneo UDP unicornscan sobre %s",ip.address)
    #unicornCmd = "unicornscan -mU -v -I %s > '%s/%s/unicordn_udp_%s@%s.txt'" % (ip,folder, ip, ip,time.strftime("%HH_%M_%S"))
    #logger.debug("Comando unicornscan: %s",unicornCmd)
    #unicornscan_results = subprocess.getoutput(unicornCmd)
    #logger.info("Unicornscan finalizado sobre %s",ip)

# Método que analiza los resultados línea a línea de un test NMAP
def analyzeNMAPResult(result):
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

# Método para analizar la línea de SO de NMAP cuando encuentra 100% de match
def processOSLine(line,services):

    if ("JUST GUESSING" in line) or ("Too many fingerprints" in line):
        # No sabemos que OS es a ciencia cierta
        nombre = "OS-Desconocido"
    elif ("Windows" in line) and not ("Linux" in line):
        # Es un Windows
        nombre = "OS-Windows"
    elif ("Linux" in line) and not ("Windows" in line):
        # Es un Linux
        nombre = "OS-Linux"
    else:
        nombre = "OS_Desconocido"

    servicio = srv.Servicio(nombre)
    servicio.puertos.append("0")
    servicio.versiones.append("0")
    servicio.estados.append("0")
    services[nombre] = servicio
