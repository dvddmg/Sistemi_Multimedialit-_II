#TODO copy this script in TD
import time, json
from os import path
from sys import path as syspath
from scapy.all import sniff, get_if_list, Ether, IP, IPv6, UDP, Raw, TCP, DNS, IPv6, ARP
from datetime import datetime
syspath.insert(0, path.abspath('dbEthOsc_LIB'))

# custom library
from dbEthOsc_LIB import *

# by default (IP:'127.0.0.1', PORT:8080)
OSC = OscSender()

PACKET_COUNT = 0

def handle_packet(pak):

    global PACKET_COUNT, OSC
    PACKET_COUNT += 1

    TMSTP = time.time()
    MSG = { 'time': TMSTP, 'pak_num': PACKET_COUNT }
    
    try:
        if ARP in pak:
            print(pak.show())

        if Ether and IP in pak:
        
            MSG['id'] = pak[IP].id
            MSG['src'] = pak[IP].src
            MSG['dst'] = pak[IP].dst

            if UDP in pak:

                MSG['udp_sport'] = pak[IP][UDP].sport
                MSG['udp_dport'] = pak[IP][UDP].dport
                MSG['len'] = pak[IP][UDP].len

                if DNS in pak:
                    MSG['dns'] = {
                        'id': pak[IP][UDP][DNS].id, # !! 16 bit assigned by the program, same for questions and relative answers
                        'qr': pak[IP][UDP][DNS].qr,
                        'qname': pak[DNS].qd.qname.decode()
                        # 'data': pak[DNS].an.rdata.decode(),
                    }

                if Raw in pak:
                    load = pak[IP][Raw].load
                    MSG['raw_data'] = list(load[:10]) if len(load) > 10 else list(load)
                    
        
                OSC.send_data('/udp', json.dumps(MSG))
                # print(f'{'-'*22} UDP {'-'*21}')
            
            if TCP in pak:
                
                MSG['len'] = pak[IP].len
                MSG['tcp_sport'] = pak[IP][TCP].sport
                MSG['tcp_dport'] = pak[IP][TCP].dport

                if Raw in pak:
                    load = pak[IP][Raw].load
                    MSG['raw_data'] = list(load[:10]) if len(load) > 10 else list(load)

                OSC.send_data('/tcp', json.dumps(MSG))
                # print(f'{'-'*22} TCP {'-'*21}')

        elif Ether and IPv6 in pak:

            # MSG['id'] = pak[IPv6].id
            MSG['src'] = pak[IPv6].src
            MSG['dst'] = pak[IPv6].dst

            if UDP in pak:

                MSG['udp_sport'] = pak[IPv6][UDP].sport
                MSG['udp_dport'] = pak[IPv6][UDP].dport
                MSG['len'] = pak[IPv6][UDP].len

                # if DNS in pak:
                #     MSG['dns'] = {
                #         'id': pak[IPv6][UDP][DNS].id, # !! 16 bit assigned by the program, same for questions and relative answers
                #         'qr': pak[IPv6][UDP][DNS].qr,
                #         'qname': pak[DNS].qd.qname.decode()
                #         # 'data': pak[DNS].an.rdata.decode(),
                #     }

                if Raw in pak:
                    load = pak[IPv6][Raw].load
                    MSG['raw_data'] = list(load[:10]) if len(load) > 10 else list(load)
                    
        
                OSC.send_data('/udp_v6', json.dumps(MSG))
                # print(f'{'-'*20} UDPV6 {'-'*20}')
                
            elif TCP in pak:
                
                # MSG['len'] = pak[IPv6].len
                MSG['tcp_sport'] = pak[IPv6][TCP].sport
                MSG['tcp_dport'] = pak[IPv6][TCP].dport

                if Raw in pak:
                    load = pak[IPv6][Raw].load
                    MSG['raw_data'] = list(load[:10]) if len(load) > 10 else list(load)

                OSC.send_data('/tcp_v6', json.dumps(MSG))
                # print(f'{'-'*20} TCPV6 {'-'*20}')
            else:
                print(pak.show())
        
                
        # now = datetime.now()
        # print(f'----------------- {now.strftime("%H:%M:%S") + f":{int(now.microsecond / 1000):03d}"} -----------------')

    except Exception as e:
        print(f'Error packet handlinig: {e}')
        print(pak)       

def interface():
    print('-'*40)

    for i, iface in enumerate(get_if_list(), 1):
        print(f"{i}: {iface}")

    print('-'*40)

if __name__ == "__main__":

    interface()

    try:
        sniff(iface=None, prn=handle_packet, store=False)

    except KeyboardInterrupt:
        print("Close program")