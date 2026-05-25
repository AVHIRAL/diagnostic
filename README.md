# AVHIRAL Linux Security Toolkit

**AVHIRAL Linux Security Toolkit** est une boîte à outils défensive destinée à auditer et durcir rapidement un système Linux, Debian ou Raspberry Pi OS avant une phase de test de cybersécurité, de validation produit ou de démonstration technique.

## Objectif

L’objectif est simple :

- analyser rapidement l’état de sécurité d’un Raspberry Pi ou serveur Linux ;
- identifier les faiblesses critiques ;
- produire un rapport lisible ;
- préparer la machine avant un audit ou un test d’intrusion encadré ;
- appliquer, si nécessaire, des protections de base via un script de durcissement séparé.

## Utilisation

`chmod +x diagnostic_linux.py
python3 -u diagnostic_linux.py --output-dir /root`

## Scripts inclus

### `diagnostic_linux.py`

Script d’audit local défensif.

Il ne modifie pas la machine.

Il vérifie notamment :

- informations système ;
- version du noyau ;
- mises à jour disponibles ;
- ports ouverts ;
- services exposés ;
- configuration SSH ;
- comptes utilisateurs ;
- sudo `NOPASSWD` ;
- permissions sensibles ;
- état du pare-feu ;
- nftables / iptables / UFW ;
- fail2ban ;
- dnsmasq ;
- durcissement `sysctl` ;
- fichiers SUID ;
- exécutables suspects dans `/tmp`, `/var/tmp`, `/dev/shm` ;
- journaux d’échecs SSH ;
- présence de services AVHIRAL comme StreamGuard.

PAYPAL DON : https://www.paypal.com/donate/?hosted_button_id=FSX7RHUT4BDRY

Le script génère un rapport en console ainsi que des fichiers :

```bash
diagnosticPi4_report_YYYYMMDD_HHMMSS.txt
diagnosticPi4_report_YYYYMMDD_HHMMSS.json
