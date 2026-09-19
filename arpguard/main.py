from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether
table = {}  # ip -> mac

def handle(pkt):
    if ARP not in pkt:
        return
    arp = pkt[ARP]
    if arp.op not in (1, 2):  # 1 = request, 2 = reply
        return
    ip, mac = arp.psrc, arp.hwsrc
    if ip == "0.0.0.0":  # ARP probe
        return

    if ip not in table:
        table[ip] = mac
        print(f"[+] Nouvelle entrée : {ip} -> {mac}")
    elif table[ip] != mac:
        print(f"[!] ALERTE : {ip} passe de {table[ip]} à {mac}")

def main():
    sniff(filter="arp", prn=handle, store=False)

if __name__ == "__main__":
    main()