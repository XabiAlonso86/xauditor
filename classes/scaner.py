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

# Método para realizar un escaneo de SMTP con NMAP
def smtpScan(ip,puerto,folder):
    logger.info("SMTP scan para %s:%s comenzado" %(ip,puerto))
    scripts = "smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764"
    cmd = "nmap -sV -Pn -p %s --script=%s %s -oN %s/smtpScan-%s@%s.txt" % (puerto,scripts,ip,folder,ip,time.strftime("%H_%M_%S"))
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final
    logger.info("SMTP scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un escaneo de SMTP con NMAP
def ftpScan(ip,puerto,folder):
    logger.info("FTP scan para %s:%s comenzado" %(ip,puerto))
    scripts = "ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221"
    cmd = "nmap -sV -Pn -p %s --script=%s -oN %s/ftpScan-%s@%s.txt %s" % (puerto,scripts,folder,ip,time.strftime("%H_%M_%S"),ip)
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final
    logger.info("FTP scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un escaneo de SMB con NMAP
def smbNmapScan(ip,puerto,folder):
    logger.info("SMB scan para %s:%s comenzado" %(ip,puerto))
    scripts = "smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse"
    cmd = "nmap --script=%s %s -oN %s/smbNmapScan-%s_%s@%s.txt" % (scripts,ip,folder,ip,puerto,time.strftime("%H_%M_%S"))
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final
    logger.info("SMB scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un escaneo de SMB con enum4linux
def enum4linuxScan(ip,puerto,folder):
    logger.info("enum4linux scan para %s:%s comenzado" %(ip,puerto))
    cmd = "enum4linux -a %s > %s/enum4linuxScan-%s_%s@%s.txt" % (ip,folder,ip,puerto,time.strftime("%H_%M_%S"))
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final
    logger.info("enum4linux scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para realizar un escaneo de mssql con NMAP
def mssqlScan(ip,puerto,folder):
    logger.info("MSSQL scan para %s:%s comenzado" %(ip,puerto))
    scripts = "ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa"
    cmd = "nmap -sV -Pn -p %s --script=%s -oN %s/mssqlScan-%s@%s.txt %s" % (puerto,scripts,folder,ip,time.strftime("%H_%M_%S"),ip)
    logger.debug("Comando: %s" % (cmd))
    results = subprocess.check_output(cmd, shell=True)
    # TODO Posible análisis y volcado a fichero final
    logger.info("MSSQL scan para %s:%s finalizado" %(ip,puerto))
    return

# Método para conectar a un puerto y devolver el resultado del banner conseguido
def conectarPuerto(ip,puerto,folder,servicio):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, int(puerto)))
    banner = s.recv(1024)
    result = "NADA"
    file = ""

    if "smtp" in servicio:
        result = banner + "\r\n"
        filePath = folder + "stmp_banner-%s@%s.txt" % (ip,time.strftime("%H_%M_%S"))
    elif "ftp" in servicio:
        s.send("USER anonymous\r\n")
        user = s.recv(1024)
        s.send("PASS anonymous\r\n")
        password = s.recv(1024)
        result = banner + "\r\n" + user + "\r\n" + password
        filePath = folder + "ftp_banner-%s@%s.txt" % (ip,time.strftime("%H_%M_%S"))
    elif "ssh" in servicio:
        result = banner
        filePath = folder + "ssh_banner-%s@%s.txt" % (ip,time.strftime("%H_%M_%S"))


    # Cerramos el socket
    s.close()
    # Escribimos los resultados en un fichero
    file = open (filePath,'w')
    file.write(result)
    file.close()
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