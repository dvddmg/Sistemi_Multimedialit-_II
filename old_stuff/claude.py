"""
Network Sniffer universale con invio dati via OSC
Cattura TUTTO il traffico di rete e lo inoltra via OSC
Richiede: pip install python-osc scapy
"""

from pythonosc import udp_client
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
import threading
import time

# ============================================
# CONFIGURAZIONE OSC
# ============================================
OSC_IP = "127.0.0.1"
OSC_PORT = 5005

# ============================================
# CLIENT OSC
# ============================================
osc_client = udp_client.SimpleUDPClient(OSC_IP, OSC_PORT)
packet_count = 0


def invia_osc(indirizzo, *valori):
    """Invia dati via OSC"""
    try:
        osc_client.send_message(indirizzo, valori)
    except Exception as e:
        print(f"Errore invio OSC: {e}")


# ============================================
# PACKET HANDLER - TUTTO IL TRAFFICO
# ============================================
def gestisci_pacchetto(pacchetto):
    """
    Gestisce OGNI pacchetto catturato e lo invia via OSC
    """
    global packet_count
    packet_count += 1
    
    try:
        timestamp = time.time()
        
        # Invia counter e timestamp
        invia_osc("/packet/count", packet_count)
        invia_osc("/packet/timestamp", timestamp)
        
        # Layer Ethernet (se presente)
        if Ether in pacchetto:
            invia_osc("/packet/eth/src", str(pacchetto[Ether].src))
            invia_osc("/packet/eth/dst", str(pacchetto[Ether].dst))
            invia_osc("/packet/eth/type", int(pacchetto[Ether].type))
        
        # Layer IP (se presente)
        if IP in pacchetto:
            invia_osc("/packet/ip/src", str(pacchetto[IP].src))
            invia_osc("/packet/ip/dst", str(pacchetto[IP].dst))
            invia_osc("/packet/ip/proto", int(pacchetto[IP].proto))
            invia_osc("/packet/ip/len", int(pacchetto[IP].len))
            invia_osc("/packet/ip/ttl", int(pacchetto[IP].ttl))
            
            # TCP
            if TCP in pacchetto:
                invia_osc("/packet/protocol", "TCP")
                invia_osc("/packet/tcp/sport", int(pacchetto[TCP].sport))
                invia_osc("/packet/tcp/dport", int(pacchetto[TCP].dport))
                invia_osc("/packet/tcp/seq", int(pacchetto[TCP].seq))
                invia_osc("/packet/tcp/ack", int(pacchetto[TCP].ack))
                invia_osc("/packet/tcp/flags", str(pacchetto[TCP].flags))
                invia_osc("/packet/tcp/window", int(pacchetto[TCP].window))
            
            # UDP
            elif UDP in pacchetto:
                invia_osc("/packet/protocol", "UDP")
                invia_osc("/packet/udp/sport", int(pacchetto[UDP].sport))
                invia_osc("/packet/udp/dport", int(pacchetto[UDP].dport))
                invia_osc("/packet/udp/len", int(pacchetto[UDP].len))
            
            # ICMP
            elif ICMP in pacchetto:
                invia_osc("/packet/protocol", "ICMP")
                invia_osc("/packet/icmp/type", int(pacchetto[ICMP].type))
                invia_osc("/packet/icmp/code", int(pacchetto[ICMP].code))
            
            # Altri protocolli IP
            else:
                proto_num = pacchetto[IP].proto
                proto_map = {6: "TCP", 17: "UDP", 1: "ICMP", 2: "IGMP", 
                            41: "IPv6", 47: "GRE", 50: "ESP", 89: "OSPF"}
                proto_name = proto_map.get(proto_num, f"PROTO_{proto_num}")
                invia_osc("/packet/protocol", proto_name)
        
        # Payload RAW (se presente)
        if Raw in pacchetto:
            payload = pacchetto[Raw].load
            payload_len = len(payload)
            
            invia_osc("/packet/payload/len", payload_len)
            
            # Invia primi 100 bytes come lista
            payload_bytes = list(payload[:100])
            invia_osc("/packet/payload/bytes", *payload_bytes)
            
            # Tenta decodifica come stringa
            try:
                payload_str = payload[:200].decode('utf-8', errors='ignore')
                if payload_str.strip():  # Solo se non vuota
                    invia_osc("/packet/payload/string", payload_str)
            except:
                pass
        
        # Lunghezza totale pacchetto
        invia_osc("/packet/total_len", len(pacchetto))
        
        # Separatore per indicare fine pacchetto
        invia_osc("/packet/end", packet_count)
        
        # Log console (ogni 10 pacchetti)
        if packet_count % 10 == 0:
            print(f"Pacchetti processati: {packet_count}")
        
    except Exception as e:
        print(f"Errore gestione pacchetto #{packet_count}: {e}")


# ============================================
# SNIFFER SENZA FILTRI
# ============================================
def avvia_sniffer(interfaccia=None):
    """
    Avvia lo sniffer SENZA filtri
    Cattura tutto il traffico di rete
    
    Args:
        interfaccia: nome interfaccia (None = tutte)
    """
    print("=" * 60)
    print("NETWORK SNIFFER UNIVERSALE -> OSC")
    print("=" * 60)
    print(f"Interfaccia: {interfaccia if interfaccia else 'TUTTE'}")
    print(f"Filtri: NESSUNO (tutto il traffico)")
    print(f"OSC output: {OSC_IP}:{OSC_PORT}")
    print("=" * 60)
    print("\nInizio cattura... (Ctrl+C per terminare)\n")
    
    # Avvia sniffing SENZA filtri
    sniff(
        iface=interfaccia,
        prn=gestisci_pacchetto,
        store=False  # Non salvare in memoria
    )


# ============================================
# LISTA INTERFACCE DISPONIBILI
# ============================================
def mostra_interfacce():
    """Mostra tutte le interfacce di rete disponibili"""
    from scapy.all import get_if_list
    
    print("\nInterfacce di rete disponibili:")
    print("-" * 40)
    for i, iface in enumerate(get_if_list(), 1):
        print(f"{i}. {iface}")
    print("-" * 40)


# ============================================
# STATISTICHE
# ============================================
def mostra_statistiche():
    """Thread per mostrare statistiche periodiche"""
    global packet_count
    last_count = 0
    
    while True:
        time.sleep(5)
        pps = (packet_count - last_count) / 5
        print(f"\n[STATS] Totale: {packet_count} | Rate: {pps:.1f} pkt/s")
        last_count = packet_count


# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    import sys
    
    print("\n" + "=" * 60)
    print("NETWORK SNIFFER COMPLETO -> OSC")
    print("=" * 60)
    
    # Mostra interfacce disponibili
    mostra_interfacce()
    
    print("\nOpzioni:")
    print("1. Cattura su TUTTE le interfacce")
    print("2. Seleziona interfaccia specifica")
    
    try:
        scelta = input("\nScelta (1-2): ").strip()
        
        interfaccia = None
        if scelta == "2":
            nome_iface = input("Nome interfaccia: ").strip()
            interfaccia = nome_iface if nome_iface else None
        
        # Avvia thread statistiche
        stats_thread = threading.Thread(target=mostra_statistiche, daemon=True)
        stats_thread.start()
        
        # Avvia sniffer
        print(interfaccia)
        avvia_sniffer(interfaccia)
        
    except KeyboardInterrupt:
        print("\n\n" + "=" * 60)
        print(f"Chiusura sniffer... Totale pacchetti: {packet_count}")
        print("=" * 60)
    except PermissionError:
        print("\n❌ ERRORE: Privilegi amministratore richiesti!")
        print("\nEsegui con:")
        print("  Linux/Mac: sudo python3 script.py")
        print("  Windows:   Esegui come Amministratore")
    except Exception as e:
        print(f"\n❌ Errore: {e}")
        import traceback
        traceback.print_exc()