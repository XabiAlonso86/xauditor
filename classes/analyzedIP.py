# -*- coding: utf-8 -*-
import logging
# Imports paquetes locales
import sistema.escaners as scn
# A falta de configuración por fichero...
logger = logging.getLogger('xauditor').getChild('analyzedIP')

class AnalizedIP:
    def __init__(self,ip,folder):
        self.ip = ip
        self.folder = folder
        self.servicios = {}
        self.serviciosUDP = {}


    # Método para analizar una IP
    def analyze(self):
        # Primero lanzamos un escaneo nmap de versiones
        self.servicios = scn.nmapScan(self.ip,self.folder)
        for nombre, servicio in self.servicios.items():
            print (nombre)
        print (len(self.servicios))
