# -*- coding: utf-8 -*-
# Imports de sistema
import subprocess
import re
import os # Para variables de sistema
import multiprocessing
from multiprocessing import Process, Queue
from threading import Thread
# Imports de paquetes propios
import sistema.operaciones as sistema

# Función para multiproceso
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

# Definición de la Clase AuditedIP
class AuditedIP(Thread):
    """docstring for ."""
    _ip_address = None
    # Constructor
    def __init__(self, ip_address, mainPath):
        try:
            Thread.__init__(self)
            self.ip_address = ip_address
            self.mainPath = mainPath
        except ValueError as ve:
            # Mandamos hacia donde hayan creado el hilo
            raise

    # Validador que la IP tiene formato correcto
    @property
    def ip_address(self):
        return self._ip_address

    @ip_address.setter
    def ip_address(self,value):
        valid = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",value)
        try:
            if not valid:
                    raise ValueError()
            self._ip_address = value
        except ValueError as ve:
            # Mandamos hacia el init de la clase
            raise

    def udpScan(self):
        print "<INFO>: Escaneo UDP sobre " + self.ip_address
        nmapCmd = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oN '%s/xauditor/%s/udp_%s.nmap' %s"  % (os.environ['HOME'],self.ip_address,self.ip_address,self.ip_address)
        print "<INFO>:" + nmapCmd
        udpscan_results = subprocess.check_output(nmapCmd, shell=True)
        print "<INFO>: Terminado escaneo UDP para " + self.ip_address
        print udpscan_results
        print "<INFO>: Escaneo UDP unicornscan sobre " + self.ip_address
        unicornCmd = "unicornscan -mU -v -I %s > '%s/xauditor/%s/unicordn_udp_%s.txt'" % (self.ip_address,os.environ['HOME'], self.ip_address, self.ip_address)
        #unicornscan_results = subprocess.check_output(unicornCmd, shell=True)
        print "<INFO>: unicornscan finalizado sobre " + self.ip_address

    # Función de escaneo NMAP
    def nmapScan(self):
        nmapCmd = "sudo nmap -sV -O %s -oN '%s/xauditor/%s/%s.nmap'" % (self.ip_address,os.environ['HOME'],self.ip_address,self.ip_address)
        print ("<INFO>: Escaneo nmap de versiones " + nmapCmd + " sobre " + self.ip_address)
        #results = subprocess.check_output(nmapCmd, shell=True)
        #print (results)

        # Lanzamos UDPScan
        p = multiprocessing.Process(target=self.udpScan, args=())
        p.start()


    # Función principal del hilo
    def run(self):
        try:
            # Creamos directorios para la IP
            dirs = os.listdir(self.mainPath)
            if not self.ip_address in dirs:
                sistema.createPath(self.mainPath, self.ip_address)
            self.nmapScan()
        # Capturamos error en subprocess
        except subprocess.CalledProcessError:
            print "<ERROR>: Subprocess Error"
