from scapy.layers.l2 import ARP, Ether
from arpguard.main import analyze, table, mac_to_ips
from arpguard.alerts import build_event

A = "aa:aa:aa:aa:aa:aa"
B = "bb:bb:bb:bb:bb:bb"

def make_arp(ip, mac, eth_src=None):
    return Ether(src=eth_src or mac) / ARP(op=2, psrc=ip, hwsrc=mac)

def types(alerts):
    return [a["type"] for a in alerts]

def setup_function():
    table.clear()
    mac_to_ips.clear()

def test_nouvelle_entree_pas_d_alerte():
    assert analyze(make_arp("192.168.1.1", A)) == []

def test_ip_change_de_mac():
    analyze(make_arp("192.168.1.1", A))
    assert "IP_MAC_CHANGE" in types(analyze(make_arp("192.168.1.1", B)))

def test_mac_multi_ip():
    analyze(make_arp("192.168.1.66", B))               # l'attaquant, avec sa vraie IP
    assert "MAC_MULTI_IP" in types(analyze(make_arp("192.168.1.1", B)))  # il usurpe la gateway

def test_ethernet_different_arp():
    assert "ETH_ARP_MISMATCH" in types(analyze(make_arp("192.168.1.1", A, eth_src=B)))


def test_event_contient_mitre():
    alert = {"type": "IP_MAC_CHANGE", "msg": "test", "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:aa"}
    event = build_event(alert)
    assert event["mitre_attack"]["id"] == "T1557.002"
    assert event["type"] == "IP_MAC_CHANGE"