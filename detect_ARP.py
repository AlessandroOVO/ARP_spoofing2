from scapy.all import ARP, sniff

# Diccionario para almacenar las direcciones IP y las MAC correspondientes
ip_mac_map = {}

def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP response (is-at), Verifica si el paquete tiene una capa ARP y si es una respuesta ARP
        src_ip = pkt[ARP].psrc #Extrae la dirección IP de origen del paquete  ARP
        src_mac = pkt[ARP].hwsrc #Extrae la dirección MAC de origen del paquete ARP

        # Verificar si la IP ya está en el diccionario
        if src_ip in ip_mac_map:
            if ip_mac_map[src_ip] != src_mac:
                print(f"[ALERTA] Posible ARP Spoofing detectado:")
                print(f"IP: {src_ip} tiene dos MACs: {ip_mac_map[src_ip]} y {src_mac}")
        else:
            ip_mac_map[src_ip] = src_mac

def start_sniffing():
    print("Empezando a monitorizar ARP en la red...")
    sniff(prn=detect_arp_spoof, filter="arp", store=0)

if __name__ == "__main__":
    start_sniffing()
