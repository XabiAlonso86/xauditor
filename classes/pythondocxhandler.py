from docx import Document
from docx.shared import RGBColor

def addTextCommand(document,cmd):
	run = document.add_paragraph().add_run(cmd)
	font = run.font
	# Color verde para la consola
	font.color.rgb = RGBColor(0x00,0x99,0x33)
	return

# Añade una lista en negrita con un texto
def addListBullet(document,value):
	document.add_paragraph(style='List Bullet').add_run(value).bold = True
	return

def addRecon(document,ip,folder):
	addListBullet(document,'Syn-scan')
    addTextCommand(document,"nmap -sS %s -oN '%s/%s_syn-scan.nmap'" % (ip,folder,ip))
    addListBullet(document,'Service-version, default scripts, OS')
    addTextCommand(document,"nmap %s -sV -sC -O -oN '%s/%s_versiones.nmap'" % (ip,folder,ip))
    addListBullet(document,'Escaneo de todos los puertos (intenso)')
    addTextCommand(document,"nmap %s -sV -sC -O -oN '%s/%s_all_ports.nmap'" % (ip,folder,ip))
    addListBullet(document,'Escaneo UDP')
    addTextCommand(document,"nmap %s -sU -oN '%s/%s_UDP.nmap'" % (ip,folder,ip))
    addTextCommand(document,"unicornscan -mU -v -I %s > '%s/%s_unicorn_scan.nmap'" % (ip,folder,ip))
    addListBullet(document,'Conexión a puerto UDP (si es posible)')
    addTextCommand(document,"nc -u %s 48772" % (ip))
    addListBullet(document,'Super Escaneo (muy intenso)')
    addTextCommand(document,"nmap %s -p- -A -T4 -sC -oN '%s/%s_UDP.nmap'" % (ip,folder,ip))
    return