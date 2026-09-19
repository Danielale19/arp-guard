# arp-guard

Détecteur d'ARP spoofing en Python (Scapy). Il écoute le trafic ARP et alerte quand une IP change soudainement d'adresse MAC.

> 🚧 Projet en cours de développement.

## Fonctionnement

Le script sniffe les paquets ARP et garde une table `IP -> MAC`. Si une IP déjà connue est annoncée avec une autre MAC, il affiche une alerte. C'est le comportement typique d'une attaque d'ARP poisoning.

## Installation

```bash
git clone https://github.com/Danielale19/arp-guard.git
cd arp-guard
python -m venv .venv
source .venv/bin/activate   # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

**Windows** : installer [Npcap](https://npcap.com) (mode compatible WinPcap) avant de lancer.

## Utilisation

Le sniff nécessite les droits root/administrateur :

```bash
sudo .venv/bin/python -m arpguard.main
```



## Limites connues

- L'outil ne voit que le trafic qui arrive à son interface. Sur un réseau switché, il doit tourner sur la machine victime (ou sur un port en mirroring) pour voir les ARP replies spoofés.
- Le premier paquet vu pour une IP sert de référence : si l'attaquant parle en premier, il devient la baseline.
- Risque de faux positifs (DHCP, VM qui change de MAC, failover).
- La table est en mémoire, elle est perdue à chaque relance.

## Roadmap

- [ ] Heuristique : une MAC qui revendique plusieurs IP
- [ ] Heuristique : MAC Ethernet ≠ MAC ARP
- [ ] Baseline persistante
- [ ] Logs JSON + mapping MITRE ATT&CK (T1557.002)
- [ ] CLI (`learn` / `monitor` / `replay`)
- [ ] Mode replay pcap
- [ ] Alertes Discord / mail
- [ ] Intégration SIEM (Wazuh / ELK)

## Avertissement

Projet à but éducatif. À tester uniquement sur un réseau de lab que tu contrôles.