# -*- coding: utf-8 -*-
import subprocess
import logging
import time
import os
# Imports local
import classes.servicio as srv

# A falta de configuración por fichero...
logger = logging.getLogger("xauditor").getChild('scaner')
# Función de escaneo NMAP
# servicios es un diccionario que vendrá de un manager para compartir memoria entre procesos
def nmapScan(ip,folder,servicios):
    # Variable Local para los servicios encontrados
    serviciosLocal = {}
    # Muy Intenso
    #nmapCmd = "nmap -vv -Pn -A -sC -sS -T4 -p- -O %s -oN '%s/%s@%s.nmap'" % (ip,folder,ip,time.strftime("%H_%M_%S"))
    # Más ligero
    nmapCmd = "nmap -sV -O %s -oN '%s/%s@%s.nmap'" % (ip,folder,ip,time.strftime("%H_%M_%S"))
    logger.info("Escaneo nmap de versiones sobre %s",ip)
    #logger.debug("Comando nmapScan: %s",nmapCmd)
    try:
        results = subprocess.getoutput(nmapCmd)
        logger.debug("Analizamos resultado nmapScan")
        # Analizamos resultados y obtenemos lista de servicios disponibles
        serviciosLocal = analyzeNMAPResult(results)
        # Mapeamos servicios uno a uno porque el manager de Python 
        # no puede detectar la asignación del objeto directamente
        for nombre, servicio in serviciosLocal.items():
            servicios[servicio.nombre] = servicio
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.exception("Escaneo NMAP sobre %s interrumpido por el usuario.",ip)

    logger.debug("Fin nmapScan para la IP %s" % (ip))
    return

   
# Función de escaneo NMAP a los puertos UDP
# servicios es un diccionario que vendrá de un manager para compartir memoria entre procesos
def nmapUdpScan(ip,folder,servicios):
    serviciosLocal = {}
    nmapCmd = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/udp_%s@%s.nmap' %s"  % (folder,ip,time.strftime("%H_%M_%S"),ip)
    logger.info("Escaneo nmap UDP sobre %s",ip)
    #logger.debug("Comando udpScan: %s",nmapCmd)
    try:
        results = subprocess.getoutput(nmapCmd)
        logger.info("Terminado escaneo UDP para %s",ip)
        serviciosLocal = analyzeNMAPResult(results)
        # Mapeamos servicios uno a uno porque el manager de Python 
        # no puede detectar la asignación del objeto directamente
        for nombre, servicio in serviciosLocal.items():
            servicios[servicio.nombre] = servicio
    # Capturamos Cierre de la aplicación por el usuario
    except KeyboardInterrupt:
        logger.error("Escaneo UDP sobre %s interrumpido por el usuario.",ip)    

    logger.debug("Fin udpScan para la IP %s" % (ip))
    return

# Método para lanzar unicornScan
def unicornScan(ip,folder):
    # Lanzamos unicornScan aunque no lo analicemos
    logger.info("Escaneo UDP unicornscan sobre %s",ip)
    unicornCmd = "unicornscan -mU -v -I %s > '%s/unicordn_udp_%s@%s.txt'" % (ip,folder,ip,time.strftime("%H_%M_%S"))
    #logger.debug("Comando unicornscan: %s",unicornCmd)
    unicornscan_results = subprocess.getoutput(unicornCmd)
    logger.info("Unicornscan finalizado sobre %s",ip)

# Método para ejecutar dirb
def dirbScan(ip, puerto, url,folder):
    logger.info("Dirb scan para %s:%s comenzado" %(ip,puerto))
    cmd = "dirb %s://%s:%s -o %s/dirbScan-%s@%s.txt -r" % (url,ip,puerto,folder,ip,time.strftime("%H_%M_%S"))
    #logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final 

    logger.info("Dirb scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para ejecutar Nikto
def niktoScan(ip, puerto, url, folder):
    logger.info("Nikto scan para %s:%s comenzado" %(ip,puerto))
    cmd = "nikto -h %s://%s:%s -o %s/niktoScan-%s-%s@%s.txt" % (url,ip,puerto,folder,url,ip,time.strftime("%H_%M_%S"))
    #logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final

    logger.info("Nikto scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un curl
def curlScan(ip,puerto,folder):
    logger.info("curl scan para %s:%s comenzado" %(ip,puerto))
    cmd = "curl -I http://%s:%s >> %s/curlScan-%s@%s.txt" % (ip,puerto,folder,ip,time.strftime("%H_%M_%S"))
    #logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final 

    logger.info("curl scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un SSLScan
def sslScan(ip,puerto,folder):
    logger.info("SSL scan para %s:%s comenzado" %(ip,puerto))
    cmd = "sslscan %s:%s >> %s/SSLScan-%s@%s.txt" % (ip,puerto,folder,ip,time.strftime("%H_%M_%S"))
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final 

    logger.info("SSL scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para lanzar scripts nmap para HTTP    
def nmapScanHTTP(ip,puerto,folder):
    logger.info("nmapScanHTTP para %s:%s comenzado" %(ip,puerto))
    scripts = "http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635"
    cmd = "nmap -sV -Pn -vv -p %s --script=%s -oN %s/nmapScanHTTP-%s@%s.nmap %s" % (puerto,scripts,folder,ip,time.strftime("%H_%M_%S"),ip)
    #logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final 

    logger.info("nmapScanHTTP para %s:%s finalizado" %(ip,puerto))
    return

# Método para lanzar análisis de nmap con scripts
def nmapScriptsLauncher(ip,puerto,folder,tipo):

    if (tipo is "HTTP"):
        nmapScanHTTP(ip,puerto,folder)

    return

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
    return

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

    return