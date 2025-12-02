import socket
import struct
from datetime import datetime
import os 
import time

# ====================================================================
# CONFIGURAZIONE (NET-HUNTER)
# ====================================================================
# Porta Bersaglio (Il cuore del tuo gioco). Lascia a None per cattura cieca.
TARGET_PORT = None 
# TARGET_PORT = 3074 

# Dimensione del blocco di analisi: ogni quanti pacchetti stampare il report
BATCH_SIZE = 200 

# ====================================================================
# FUNZIONI CORE (Non modificate per l'efficacia del parsing)
# ====================================================================

def create_sniffer():
    """Stabilisce il gancio di rete."""
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        
        # Tentativo di binding all'IP locale per mitigare WinError 10022
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        print(f"[!] Bind IP: {local_ip}")
        sniffer.bind((local_ip, 0))
        
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        if os.name == 'nt': 
             print("[!] Abilitazione SIO_RCVALL (Promiscuo Windows)...")
             sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        return sniffer
    except PermissionError:
        print("[-] ERRORE: Permesso negato. Necessari privilegi di ROOT/ADMIN.")
        return None
    except Exception as e:
        if "SIO_RCVALL" in str(e) and os.name != 'nt':
             print("[!] AVVISO: SIO_RCVALL fallito (Atteso su non-Windows).")
             return sniffer
        print(f"[-] ERRORE: Errore critico nel socket: {e}")
        return None

def parse_ip_header(packet):
    """Analizza il livello 3 (IP)."""
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    ihl = (iph[0] & 0xF)
    protocol = iph[6]
    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])
    
    return {'ihl': ihl, 'protocol': protocol, 'src': src_addr, 'dst': dst_addr}

def parse_tcp_header(packet, ip_ihl):
    """Analizza il livello 4 (TCP)."""
    tcp_start = ip_ihl * 4 
    if len(packet) < tcp_start + 20: return {}
    tcph = struct.unpack('!HHLLBBHHH', packet[tcp_start : tcp_start + 20])
    return {'src_port': tcph[0], 'dst_port': tcph[1]}

def parse_udp_header(packet, ip_ihl):
    """Analizza il livello 4 (UDP)."""
    udp_start = ip_ihl * 4 
    if len(packet) < udp_start + 8: return {}
    udph = struct.unpack('!HHHH', packet[udp_start : udp_start + 8])
    return {'src_port': udph[0], 'dst_port': udph[1]}

def get_protocol_name(protocol_num):
    """Mappa il protocollo numerico al nome."""
    protocols = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
    return protocols.get(protocol_num, f'L{protocol_num}')

# ====================================================================
# ESECUZIONE PRINCIPALE (OPERAZIONE)
# ====================================================================

def main():
    print("="*50)
    print("       NET-HUNTER: ANALIZZATORE FLUSSO GIOCHI       ")
    print("="*50)
    if TARGET_PORT:
        print(f"[+] FILTRO ATTIVO: Solo Porta {TARGET_PORT}")
    else:
        print("[!] FILTRO DISATTIVATO: Cattura tutti i flussi.")
    print(f"[!] Report generato ogni {BATCH_SIZE} pacchetti. CTRL+C per terminare.")
    print("="*50 + "\n")
    
    sniffer = create_sniffer()
    if not sniffer:
        return
    
    ip_addresses = set()
    packet_count = 0
    flow_counter = {} # Key: (src_ip, src_port, dst_ip, dst_port, protocol)
    
    try:
        while True:
            sniffer.settimeout(0.5) 
            try:
                packet, addr = sniffer.recvfrom(65565)
            except socket.timeout:
                continue

            packet_count += 1
            
            # Analisi L3
            ip_info = parse_ip_header(packet)
            protocol = ip_info['protocol']
            ip_ihl = ip_info['ihl'] 
            
            port_info = {}
            if protocol == 6: 
                port_info = parse_tcp_header(packet, ip_ihl)
            elif protocol == 17: 
                port_info = parse_udp_header(packet, ip_ihl)
            
            # Dati per la chiave
            src_port = port_info.get('src_port', 0)
            dst_port = port_info.get('dst_port', 0)
            
            # FILTRO PORTA
            if TARGET_PORT is not None:
                if src_port != TARGET_PORT and dst_port != TARGET_PORT:
                    continue
            
            # Creazione e incremento chiave
            flow_key = (ip_info['src'], src_port, ip_info['dst'], dst_port, protocol)
            flow_counter[flow_key] = flow_counter.get(flow_key, 0) + 1
            ip_addresses.add(ip_info['src'])
            ip_addresses.add(ip_info['dst'])

            # -------------------------------------------------------------------
            # RIASSUNTO E REPORT (Stile terminale)
            # -------------------------------------------------------------------
            if packet_count % BATCH_SIZE == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"\n[{timestamp}] >> REPORT BATCH {packet_count} (Flussi più attivi) <<")
                
                # Ordina i flussi dal più frequente (più traffico = più importante)
                sorted_flows = sorted(flow_counter.items(), key=lambda item: item[1], reverse=True)
                
                for key, count in sorted_flows:
                    src_ip, src_port, dst_ip, dst_port, proto_num = key
                    proto_name = get_protocol_name(proto_num)
                    
                    if src_port != 0:
                        # Formato IP:PORTA
                        flow_desc = f"{src_ip}:{src_port} --{proto_name}--> {dst_ip}:{dst_port}"
                    else:
                        # Formato solo IP
                        flow_desc = f"{src_ip} --{proto_name}--> {dst_ip}"
                        
                    # Stampa in stile log (esempio: [TCP] 192.168.1.10:50000 -> 8.8.8.8:53 | x120 HITS)
                    print(f"   | [{proto_name}] {flow_desc} | x{count} HITS")

                # Statistiche IP unici
                print(f"\n   [INFO] Totale IP unici registrati: {len(ip_addresses)}")
                
                # Reset del contatore
                flow_counter = {}
                
    except KeyboardInterrupt:
        print("\n\n[!] GANCIO CHIUSO: Sessione terminata dall'utente.")
        print(f"[!] Rete monitorata. IP unici registrati: {len(ip_addresses)}")
        for ip in sorted(ip_addresses):
            print(f"  - {ip}")
    except Exception as e:
        print(f"[-] ERRORE in runtime: {e}")
    finally:
        if sniffer and os.name == 'nt':
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass 

if __name__ == "__main__":
    main()