import sys
import os
import time
import subprocess # <-- ESSENZIALE: Per eseguire programmi esterni
import ctypes
from pathlib import Path

# Definizione della cartella dei moduli
BIN_DIR = "bin"
TIMEOUT_WAIT = 5 # Timeout per l'attesa finale dell'attacco

# Colori in stile Terminale (ANSI escape codes)
class C:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    END = '\033[0m'
    BOLD = '\033[1m'

# ==============================================================================
#           FUNZIONI CORE DI SICUREZZA E PREPARAZIONE
# ==============================================================================

def check_admin_privileges():
    """
    Controlla i privilegi di amministratore (Windows) o root (Linux/macOS).
    Se i privilegi non sono presenti, avverte e termina.
    """
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin = False
            
        if not is_admin:
            print(f"{C.RED}[CRITICAL] ERRORE: Privilegi Amministrativi non trovati.{C.END}")
            print(f"{C.YELLOW}SUGGERIMENTO: Esegui il 'CYBER_OPS_GATEWAY' con 'Esegui come Amministratore'.{C.END}")
            return False
    else:
        if os.geteuid() != 0:
            print(f"{C.RED}[CRITICAL] ERRORE: Privilegi ROOT (UID 0) non trovati.{C.END}")
            print(f"{C.YELLOW}SUGGERIMENTO: Esegui con 'sudo python cyber_ops_gateway.py'.{C.END}")
            return False
            
    print(f"{C.GREEN}[STATUS] Accesso Amministrativo/Root verificato. Procedo...{C.END}")
    return True

def setup_module_path():
    """Verifica la presenza dei file operativi nella cartella bin."""
    
    files_to_check = ['dosv2.py', 'sniffergame.py']
    missing_files = []
    
    # Non modifichiamo sys.path, verifichiamo solo l'esistenza
    for filename in files_to_check:
        full_path = Path(BIN_DIR) / filename
        if not full_path.exists():
            missing_files.append(filename)
            
    if missing_files:
        print(f"{C.RED}[FATAL ERROR] Impossibile trovare i moduli operativi richiesti.{C.END}")
        print(f"{C.RED}MANCANO: {', '.join(missing_files)}{C.END}")
        print(f"{C.YELLOW}VERIFICA: I file devono essere posizionati in una cartella '{BIN_DIR}/' nella directory di esecuzione.{C.END}")
        return False
        
    return True

# ==============================================================================
#               MODULO DI GESTIONE INTERFACCIA (GATEWAY)
# ==============================================================================

def print_banner():
    """Visualizza il banner iniziale in stile console hacker."""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{C.BOLD}{C.BLUE}" + "="*60 + f"{C.END}")
    print(f"{C.BOLD}{C.BLUE}       >>> {C.GREEN}C Y B E R - O P S   G A T E W A Y{C.BLUE} <<<      {C.END}")
    print(f"{C.BOLD}{C.BLUE}             | Unified Network Toolkit |           {C.END}")
    print(f"{C.BOLD}{C.BLUE}                {C.GREEN}RUNNING AS ROOT/ADMIN{C.BLUE}               {C.END}")
    print(f"{C.BOLD}{C.BLUE}" + "="*60 + f"{C.END}\n")

def menu_selection():
    """Mostra il menu di selezione e gestisce l'input."""
    print(f"{C.YELLOW}Seleziona un Modulo Operativo:{C.END}")
    print(f"   {C.GREEN}1. [EXECUTE] {C.END}{C.BOLD}DOS/Flood Vector{C.END} - Invia pacchetti UDP al target.")
    print(f"   {C.GREEN}2. [MONITOR] {C.END}{C.BOLD}Packet Sniffer{C.END} - Analisi passiva del traffico di rete.")
    print(f"   {C.RED}0. [EXIT] {C.END}Termina la sessione.\n")
    
    while True:
        choice = input(f"{C.BOLD}COMMAND (1, 2, 0):{C.END} ").strip()
        if choice in ['1', '2', '0']:
            return choice
        print(f"{C.RED}[ERROR] Selezione non valida. Riprova.{C.END}")

def build_command(script_name):
    """Costruisce il comando di esecuzione, assicurandosi che il percorso sia corretto."""
    script_path = Path(BIN_DIR) / script_name
    
    # Esegui l'interprete Python sul file script
    command = [sys.executable, str(script_path)]
    
    # Nota: su Linux/macOS, se il gateway è avviato con sudo, il subprocess
    # eredita i permessi. Non è necessario chiamare 'sudo' esplicitamente qui.
    return command

def execute_flood_module():
    """Lancia lo script DOS/Flood come sottoprocesso."""
    print_banner()
    print(f"{C.GREEN}[INFO] Avvio Modulo: DOS/Flood Vector...{C.END}")
    
    command = build_command("dosv2.py")
    
    try:
        # Esegui il modulo e attendi la sua conclusione. 
        # L'attacco è interattivo (chiede input e mostra progress bar), quindi usiamo Popen.
        process = subprocess.Popen(command)
        process.wait()
        
    except KeyboardInterrupt:
        print(f"\n{C.RED}[ABORT] Terminazione del sottoprocesso Flood.{C.END}")
        if process.poll() is None:
            process.terminate() 
    except Exception as e:
        print(f"\n{C.RED}[CRITICAL ERROR] Fallimento del modulo Flood: {e}{C.END}")
        
    time.sleep(TIMEOUT_WAIT) 
    
def execute_sniffer_module():
    """Lancia lo script Sniffer come sottoprocesso."""
    print_banner()
    print(f"{C.GREEN}[INFO] Avvio Modulo: Packet Sniffer (NET-HUNTER)...{C.END}")
    
    command = build_command("sniffergame.py")
    
    try:
        print(f"{C.YELLOW}WARNING: Il modulo Sniffer rimarrà attivo. Premi CTRL+C per tornare al Gateway.{C.END}")
        
        # Esegui il modulo e attendi che l'utente lo interrompa con CTRL+C
        process = subprocess.Popen(command)
        process.wait()
        
    except KeyboardInterrupt:
        # Se l'utente preme CTRL+C nel Gateway, catturiamo l'interruzione qui
        print(f"\n{C.RED}[ABORT] Interruzione del sottoprocesso Sniffer.{C.END}")
    except Exception as e:
         print(f"\n{C.RED}[CRITICAL ERROR] Fallimento del modulo Sniffer: {e}{C.END}")
    finally:
        # Pulizia: se il processo è ancora attivo, lo terminiamo.
        if process.poll() is None:
            print(f"{C.YELLOW}[CLEANUP] Terminazione forzata del processo Sniffer.{C.END}")
            process.terminate() 
            time.sleep(1)
            if process.poll() is None:
                process.kill()

# ==============================================================================
#                           PUNTO DI INGRESSO
# ==============================================================================

if __name__ == "__main__":
    try:
        # 1. Verifica i privilegi necessari
        if not check_admin_privileges():
            sys.exit(1)
            
        # 2. Verifica la struttura delle cartelle e dei moduli
        if not setup_module_path():
            sys.exit(1)
            
        # 3. Loop principale del Gateway
        while True:
            print_banner()
            
            CHOICE = menu_selection()
            
            if CHOICE == '1':
                execute_flood_module()
            elif CHOICE == '2':
                execute_sniffer_module()
            elif CHOICE == '0':
                print(f"\n{C.YELLOW}[SHUTDOWN] Terminazione del Gateway. Sessione conclusa.{C.END}")
                sys.exit(0)
                
    except KeyboardInterrupt:
        print(f"\n{C.RED}[ABORT] Interruzione del Gateway. Sessione terminata.{C.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{C.RED}[UNEXPECTED CRASH] Errore critico nel ciclo principale: {e}{C.END}")
        sys.exit(1)