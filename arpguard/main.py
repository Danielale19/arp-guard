from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether

from arpguard.alerts import build_event, write_event

table = {}        # ip -> mac
mac_to_ips = {}   # mac -> set d'IP


def analyze(pkt):
    """Analyse un paquet et renvoie la liste des alertes (vide si RAS)."""
    alerts = []
    if ARP not in pkt:
        return alerts
    arp = pkt[ARP]
    if arp.op not in (1, 2):
        return alerts

    ip, mac = arp.psrc, arp.hwsrc.lower()
    if ip == "0.0.0.0":  # ARP probe
        return alerts

    # H3 : MAC Ethernet != MAC ARP
    if Ether in pkt and pkt[Ether].src.lower() != mac:
        alerts.append({
            "type": "ETH_ARP_MISMATCH",
            "msg": f"Ethernet src {pkt[Ether].src} != ARP hwsrc {mac} (IP {ip})",
            "ip": ip,
            "mac": mac,
        })

    # H1 : une IP change de MAC
    if ip not in table:
        table[ip] = mac
    elif table[ip] != mac:
        alerts.append({
            "type": "IP_MAC_CHANGE",
            "msg": f"{ip} passe de {table[ip]} à {mac}",
            "ip": ip,
            "mac": mac,
        })

    # H2 : une MAC annonce plusieurs IP
    ips = mac_to_ips.setdefault(mac, set())
    if ips and ip not in ips:
        alerts.append({
            "type": "MAC_MULTI_IP",
            "msg": f"{mac} annonce plusieurs IP : {sorted(ips | {ip})}",
            "ip": ip,
            "mac": mac,
        })
    ips.add(ip)

    return alerts


def handle(pkt):
    for a in analyze(pkt):
        print(f"[!] ALERTE [{a['type']}] {a['msg']}")
        write_event(build_event(a))


def main():
    sniff(filter="arp", prn=handle, store=False)


if __name__ == "__main__":
    main()