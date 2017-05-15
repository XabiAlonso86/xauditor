# -*- coding: utf-8 -*-
import logging
import time
import subprocess
# Paquetes locales
import classes.servicio as srv

# A falta de configuración por fichero...
logger = logging.getLogger('xauditor').getChild('escaners')

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

# Método para analizar la línea de SO de NMAP cuando encuentra 100%
def processOSLine(line,services):

    if ("JUST GUESSING" in line):
        # No sabemos que OS es a ciencia cierta
        nombre = "OS-Desconocido"
    elif ("Windows" in line) and not ("Linux" in line):
        # Es un Windows
        nombre = "OS-Windows"
    elif ("Linux" in line) and not ("Windows" in line):
        # Es un Linux
        nombre = "OS-Linux"

    servicio = srv.Servicio(nombre)
    servicio.puertos.append("0")
    servicio.versiones.append("0")
    servicio.estados.append("0")
    services[nombre] = servicio

# Método que analiza los resultados línea a línea de un test NMAP
def analyzeNMAP(result):

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

# Función de escaneo NMAP
def nmapScan(ip, folder):
    nmapCmd = "sudo nmap -sV -O %s -oN '%s/%s/%s@%s.nmap'" % (ip,folder,ip,ip,time.strftime("%HH_%M_%S"))
    logger.info("Escaneo nmap de versiones sobre %s",ip)
    logger.debug("Comando nmapScan: %s",nmapCmd)
    try:
        results = subprocess.getoutput(nmapCmd)
        # Analizamos resultados y obtenemos lista de servicios disponibles
        services = analyzeNMAP(results)
        return services
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.exception("Escaneo TCP Version sobre %s interrumpido por el usuario.",ip)
    #print (results)

    # Lanzamos UDPScan
    #p = multiprocessing.Process(target=udpScan, args=(ip_address, mainPath))
    #p.start()


# Función de escaneo NMAP a los puertos UDP
def udpScan(ip, folder):
    logger.info("Escaneo UDP sobre %s",ip)
    nmapCmd = "sudo nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/%s/udp_%s@%s.nmap' %s"  % (folder,ip,ip,ip,time.strftime("%HH_%M_%S"))
    logger.info("Escaneo nmap UDP sobre %s",ip)
    logger.debug("Comando udpScan: %s",nmapCmd)
    try:
        udpscan_results = subprocess.getoutput(nmapCmd)
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.error("Escaneo UDP sobre %s interrumpido por el usuario.",ip)

    logger.info("Terminado escaneo UDP para %s",ip.address)
    print (udpscan_results)
    logger.info("Escaneo UDP unicornscan sobre %s",ip.address)
    unicornCmd = "unicornscan -mU -v -I %s > '%s/%s/unicordn_udp_%s@%s.txt'" % (ip,folder, ip, ip,time.strftime("%HH_%M_%S"))
    logger.debug("Comando unicornscan: %s",unicornCmd)
    #unicornscan_results = subprocess.getoutput(unicornCmd)
    logger.info("Unicornscan finalizado sobre %s",ip)
