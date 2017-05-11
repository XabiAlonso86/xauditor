# Imports de sistema
import subprocess
import re
import os # Para variables de sistema
from threading import Thread
# Imports de paquetes propios
import sistema.operaciones as sistema

class AuditedIP(Thread):
    """docstring for ."""
    _ip_address = None
    def __init__(self, ip_address, mainPath):
        Thread.__init__(self)
        self.ip_address = ip_address
        self.mainPath = mainPath

    # Validador que la IP tiene formato correcto
    @property
    def ip_address(self):
        return self._ip_address

    @ip_address.setter
    def ip_address(self,value):
        valid = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",value)
        if not valid:
            raise Exception("IP " + value + " tiene un formato incorrecto")
        self._ip_address = value

    def nmapScan(self):
        nmapCmd = "sudo nmap -sV -O %s -oN '%s/%s/%s/%s.nmap'" % (self.ip_address,os.environ['HOME'],"xauditor",self.ip_address,self.ip_address)
        print ("lanzo " + nmapCmd)
        results = subprocess.check_output(nmapCmd, shell=True)
        print (results)

    def run(self):
        # Creamos directorios para la IP
        dirs = os.listdir(self.mainPath)
        if not self.ip_address in dirs:
            sistema.createPath(self.mainPath, self.ip_address)
        self.nmapScan()
