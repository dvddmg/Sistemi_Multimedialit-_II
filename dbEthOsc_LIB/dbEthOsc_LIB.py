# from scapy.all import sniff, IP, TCP, UDP, UCMP, Raw, Ether
from pythonosc import udp_client

class OscSender:
    '''
    Istance a new SimpleUDPClient and send osc message
    '''
    def __init__(self, IP="127.0.0.1", PORT=8080):
        self.ip = IP
        self.port = PORT
        self.client = udp_client.SimpleUDPClient(IP, PORT)

    @property
    def IP(self):
        return self.ip
    
    @property
    def PORT(self):
        return self.port
    
    def send_data(self, address="/", *vals):
        try:
            self.client.send_message(address=address, value=vals)
        except Exception as e:
            print(f"Error send OSC: {e}")