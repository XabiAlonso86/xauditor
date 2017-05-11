import subprocess
def createMainPath(mainPath):
    print ("Creando Path de la aplicación en " + mainPath)
    subprocess.check_output("mkdir " + mainPath, shell=True)

def createPath(mainPath, ip_address):
    print ("Creando Folders para IP " + ip_address)
    subprocess.check_output("mkdir " + mainPath + "/" + ip_address, shell=True)
