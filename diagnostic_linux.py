#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AVHIRAL diagnosticPi4.py
Audit local défensif d'un Raspberry Pi 4 / Debian / Raspberry Pi OS.
Objectif : vérifier rapidement la posture sécurité avant tests CyberCampus.

Usage :
  sudo python3 diagnosticPi4.py
  sudo python3 diagnosticPi4.py --no-color
  sudo python3 diagnosticPi4.py --json-only

Aucune dépendance externe. Le script ne modifie rien sur la machine.
"""

import argparse
import datetime as _dt
import glob
import grp
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

VERSION = "1.0"
APP_NAME = "AVHIRAL diagnosticPi4"

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
    "OK": 0,
}
SEVERITY_PENALTY = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
    "OK": 0,
}

DEFAULT_EXPECTED_OPEN_PORTS = {
    # Ajuste si besoin selon le rôle exact du Raspberry.
    22: "SSH administration",
    53: "DNS local/dnsmasq",
    80: "HTTP local",
    443: "HTTPS local",
    5000: "API locale AVHIRAL/IRONWALL/StreamGuard éventuelle",
    8088: "Portail local AVHIRAL StreamGuard",
    2052: "Port portail StreamGuard pour test IPTV",
    2053: "Port portail StreamGuard pour test IPTV",
    2082: "Port portail StreamGuard pour test IPTV",
    2083: "Port portail StreamGuard pour test IPTV",
    2086: "Port portail StreamGuard pour test IPTV",
    2087: "Port portail StreamGuard pour test IPTV",
    2095: "Port portail StreamGuard pour test IPTV",
    2096: "Port portail StreamGuard pour test IPTV",
    8000: "Port portail StreamGuard pour test IPTV",
    8080: "Port portail StreamGuard pour test IPTV",
    8443: "Port portail StreamGuard pour test IPTV",
    8880: "Port portail StreamGuard pour test IPTV",
    25443: "Port portail StreamGuard pour test IPTV",
    25461: "Port portail StreamGuard pour test IPTV",
    25500: "Port portail StreamGuard pour test IPTV",
}

DANGEROUS_PORTS = {
    21: "FTP non chiffré",
    23: "Telnet non chiffré",
    25: "SMTP exposé",
    111: "rpcbind",
    139: "NetBIOS",
    445: "SMB/Samba",
    512: "rsh",
    513: "rlogin",
    514: "rexec/syslog distant",
    873: "rsync daemon",
    2049: "NFS",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

HIGH_RISK_SERVICES = [
    "telnet", "telnetd", "vsftpd", "proftpd", "pure-ftpd", "xrdp", "vnc", "vncserver",
    "smbd", "nmbd", "rpcbind", "nfs-server", "cups", "avahi-daemon", "bluetooth",
    "redis", "mysql", "mariadb", "postgresql", "docker", "portainer",
]

class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.reset = "\033[0m" if enabled else ""
        self.bold = "\033[1m" if enabled else ""
        self.red = "\033[31m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""
        self.magenta = "\033[35m" if enabled else ""

    def sev(self, severity):
        if not self.enabled:
            return severity
        if severity == "CRITICAL":
            return f"{self.bold}{self.red}{severity}{self.reset}"
        if severity == "HIGH":
            return f"{self.red}{severity}{self.reset}"
        if severity == "MEDIUM":
            return f"{self.yellow}{severity}{self.reset}"
        if severity == "LOW":
            return f"{self.cyan}{severity}{self.reset}"
        if severity == "OK":
            return f"{self.green}{severity}{self.reset}"
        return f"{self.blue}{severity}{self.reset}"

class Finding:
    def __init__(self, section, severity, title, detail="", remediation=""):
        self.section = section
        self.severity = severity
        self.title = title
        self.detail = detail.strip() if detail else ""
        self.remediation = remediation.strip() if remediation else ""

    def as_dict(self):
        return {
            "section": self.section,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
        }

class Auditor:
    def __init__(self, args):
        self.args = args
        self.findings = []
        self.raw = {}
        self.started = time.time()
        self.now = _dt.datetime.now().astimezone()
        self.hostname = socket.gethostname()
        self.output_dir = Path(args.output_dir).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def add(self, section, severity, title, detail="", remediation=""):
        if severity not in SEVERITY_ORDER:
            severity = "INFO"
        self.findings.append(Finding(section, severity, title, detail, remediation))

    def run(self, cmd, timeout=8, shell=False):
        try:
            if shell:
                p = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            else:
                p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout après {timeout}s"
        except FileNotFoundError as e:
            return 127, "", str(e)
        except Exception as e:
            return 1, "", repr(e)

    def read_text(self, path, max_bytes=1024 * 512):
        try:
            p = Path(path)
            if not p.exists():
                return ""
            with p.open("rb") as f:
                data = f.read(max_bytes)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def exists_cmd(self, name):
        return shutil.which(name) is not None

    def collect_system_info(self):
        section = "Système"
        os_release = self.read_text("/etc/os-release")
        uname = platform.uname()
        self.raw["os_release"] = os_release
        self.raw["uname"] = uname._asdict()
        self.raw["is_root"] = os.geteuid() == 0

        detail = [
            f"Hôte: {self.hostname}",
            f"Kernel: {uname.system} {uname.release} {uname.machine}",
            f"Python: {platform.python_version()}",
        ]
        pretty = ""
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
        if pretty:
            detail.append(f"OS: {pretty}")
        self.add(section, "INFO", "Informations système", "\n".join(detail))

        if os.geteuid() != 0:
            self.add(section, "MEDIUM", "Script lancé sans privilèges root", "Certaines vérifications seront incomplètes.", "Relancer avec : sudo python3 diagnosticPi4.py")
        else:
            self.add(section, "OK", "Script lancé en root", "Audit local complet possible.")

        # Raspberry Pi model
        model = self.read_text("/proc/device-tree/model", 4096).replace("\x00", "").strip()
        if model:
            self.raw["raspberry_model"] = model
            if "Raspberry Pi" in model:
                self.add(section, "OK", "Matériel Raspberry détecté", model)
            else:
                self.add(section, "INFO", "Modèle matériel", model)

        # Boot time / uptime
        rc, out, _ = self.run(["uptime", "-p"], timeout=3)
        if rc == 0:
            self.add(section, "INFO", "Uptime", out)

    def check_updates(self):
        section = "Mises à jour"
        if not self.exists_cmd("apt"):
            self.add(section, "INFO", "APT non détecté", "Système non-Debian ou environnement minimal.")
            return

        rc, out, err = self.run(["apt", "list", "--upgradable"], timeout=20)
        if rc != 0:
            self.add(section, "LOW", "Impossible de lister les paquets à mettre à jour", err or out, "Vérifier manuellement : apt update && apt list --upgradable")
            return
        lines = [l for l in out.splitlines() if l and not l.startswith("Listing")]
        self.raw["upgradable_packages"] = lines[:200]
        kernel_updates = [l for l in lines if re.search(r"linux-image|raspberrypi-kernel|firmware", l, re.I)]
        if len(lines) == 0:
            self.add(section, "OK", "Aucun paquet à mettre à jour détecté", "Selon le cache APT local actuel.")
        elif len(lines) <= 10:
            self.add(section, "LOW", f"{len(lines)} paquet(s) à mettre à jour", "\n".join(lines[:10]), "Exécuter : apt update && apt full-upgrade")
        else:
            self.add(section, "MEDIUM", f"{len(lines)} paquet(s) à mettre à jour", "\n".join(lines[:20]), "Exécuter : apt update && apt full-upgrade, puis redémarrer si noyau/firmware.")
        if kernel_updates:
            self.add(section, "HIGH", "Mise à jour noyau/firmware disponible", "\n".join(kernel_updates[:10]), "Appliquer rapidement puis redémarrer : reboot")

        rc, out, _ = self.run(["dpkg", "-s", "unattended-upgrades"], timeout=6)
        if rc == 0:
            self.add(section, "OK", "unattended-upgrades installé", "Les mises à jour automatiques peuvent être configurées.")
        else:
            self.add(section, "LOW", "unattended-upgrades non installé", "Les correctifs de sécurité ne seront pas appliqués automatiquement.", "Installer/configurer : apt install unattended-upgrades apt-listchanges")

    def parse_ss(self, out):
        entries = []
        for line in out.splitlines():
            if not line or line.startswith("Netid"):
                continue
            parts = re.split(r"\s+", line.strip(), maxsplit=6)
            if len(parts) < 5:
                continue
            netid = parts[0]
            state = parts[1] if netid in ("tcp", "tcp6") else "UNCONN"
            local = parts[4] if netid in ("tcp", "tcp6") else parts[4]
            process = parts[6] if len(parts) > 6 else ""
            port = None
            addr = local
            # Formats: 0.0.0.0:22, [::]:22, *:53
            m = re.search(r":(\d+)$", local)
            if m:
                port = int(m.group(1))
                addr = local[: local.rfind(":")]
            entries.append({"proto": netid, "state": state, "local": local, "addr": addr, "port": port, "process": process})
        return entries

    def check_listening_ports(self):
        section = "Surface réseau"
        if self.exists_cmd("ss"):
            rc, out, err = self.run(["ss", "-tulpen"], timeout=8)
        else:
            rc, out, err = self.run(["netstat", "-tulpen"], timeout=8)
        if rc != 0:
            self.add(section, "MEDIUM", "Impossible de lire les ports en écoute", err or out, "Installer iproute2 ou net-tools.")
            return
        entries = self.parse_ss(out)
        self.raw["listening_sockets"] = entries
        if not entries:
            self.add(section, "OK", "Aucun port en écoute détecté", "Très restrictif, mais vérifier que les services attendus fonctionnent.")
            return

        exposed = []
        unexpected = []
        dangerous = []
        for e in entries:
            port = e.get("port")
            local = e.get("local", "")
            addr = e.get("addr", "")
            proc = e.get("process", "")
            if port is None:
                continue
            binds_all = addr in ("0.0.0.0", "*", "[::]", "::") or local.startswith("*: ")
            row = f"{e['proto']} {local} {proc}"
            if binds_all:
                exposed.append(row)
            if port in DANGEROUS_PORTS:
                dangerous.append(f"{row} => {DANGEROUS_PORTS[port]}")
            if port not in DEFAULT_EXPECTED_OPEN_PORTS:
                unexpected.append(row)

        self.add(section, "INFO", "Ports en écoute", "\n".join([f"{e['proto']} {e['local']} {e.get('process','')}" for e in entries[:80]]))

        if dangerous:
            self.add(section, "HIGH", "Services dangereux ou sensibles exposés", "\n".join(dangerous), "Désactiver le service s'il n'est pas strictement nécessaire ou limiter à l'interface LAN/VPN.")
        if unexpected:
            self.add(section, "MEDIUM", "Ports non prévus détectés", "\n".join(unexpected[:40]), "Valider chaque service. Fermer tout port inutile avant les tests CyberCampus.")
        if exposed:
            self.add(section, "LOW", "Services bindés sur toutes les interfaces", "\n".join(exposed[:60]), "Préférer une écoute sur l'IP LAN uniquement ou localhost selon le besoin.")
        if not dangerous and not unexpected:
            self.add(section, "OK", "Surface réseau cohérente", "Aucun port fortement suspect détecté par la politique intégrée.")

    def check_firewall(self):
        section = "Pare-feu"
        nft_out = ""
        if self.exists_cmd("nft"):
            rc, nft_out, err = self.run(["nft", "list", "ruleset"], timeout=10)
            self.raw["nft_ruleset_excerpt"] = nft_out[:20000]
            if rc != 0:
                self.add(section, "MEDIUM", "nftables présent mais ruleset illisible", err or nft_out, "Vérifier : nft list ruleset")
            elif not nft_out.strip():
                self.add(section, "HIGH", "Aucune règle nftables active", "Le Pi semble sans filtrage noyau nftables.", "Activer nftables/ufw ou des règles input/forward explicites.")
            else:
                has_input = bool(re.search(r"hook\s+input", nft_out))
                has_forward = bool(re.search(r"hook\s+forward", nft_out))
                has_drop_reject = bool(re.search(r"\b(drop|reject)\b", nft_out))
                has_avhiral = "avhiral_streamguard_ai" in nft_out or "avhiral" in nft_out.lower()
                details = []
                details.append(f"hook input: {'oui' if has_input else 'non'}")
                details.append(f"hook forward: {'oui' if has_forward else 'non'}")
                details.append(f"drop/reject: {'oui' if has_drop_reject else 'non'}")
                details.append(f"règles AVHIRAL: {'oui' if has_avhiral else 'non'}")
                if has_input and has_drop_reject:
                    self.add(section, "OK", "nftables actif", "\n".join(details))
                elif has_avhiral and has_drop_reject:
                    self.add(section, "LOW", "nftables actif mais politique input à confirmer", "\n".join(details), "Ajouter une chaîne input restrictive si le Pi est exposé.")
                else:
                    self.add(section, "MEDIUM", "nftables présent mais filtrage faible ou incomplet", "\n".join(details), "Mettre en place une politique input par défaut en drop avec exceptions LAN nécessaires.")

        if self.exists_cmd("ufw"):
            rc, out, _ = self.run(["ufw", "status", "verbose"], timeout=6)
            self.raw["ufw_status"] = out
            if "Status: active" in out:
                self.add(section, "OK", "UFW actif", out)
            else:
                self.add(section, "LOW", "UFW inactif", out or "ufw installé mais inactif")
        else:
            self.add(section, "INFO", "UFW non installé", "Ce n'est pas bloquant si nftables est configuré proprement.")

        if self.exists_cmd("iptables"):
            rc, out, _ = self.run(["iptables", "-S"], timeout=8)
            self.raw["iptables_s"] = out[:12000]
            if rc == 0 and out.strip() and "-P INPUT ACCEPT" in out and "DROP" not in out and "REJECT" not in out:
                self.add(section, "LOW", "iptables semble permissif", "INPUT ACCEPT sans DROP/REJECT visibles.", "Sur systèmes nftables, iptables peut être secondaire ; vérifier nft list ruleset.")

    def ssh_effective_config(self):
        if self.exists_cmd("sshd"):
            rc, out, err = self.run(["sshd", "-T"], timeout=8)
            if rc == 0 and out:
                cfg = {}
                for line in out.splitlines():
                    if not line.strip():
                        continue
                    k, _, v = line.partition(" ")
                    cfg[k.lower()] = v.strip()
                return cfg, "sshd -T"
        # fallback parse config files simply
        files = ["/etc/ssh/sshd_config"] + sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
        cfg = {}
        for f in files:
            txt = self.read_text(f)
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if " " in line or "\t" in line:
                    k, v = re.split(r"\s+", line, maxsplit=1)
                    cfg[k.lower()] = v.strip()
        return cfg, "parse fichiers"

    def check_ssh(self):
        section = "SSH"
        active = None
        if self.exists_cmd("systemctl"):
            rc, out, _ = self.run(["systemctl", "is-active", "ssh"], timeout=4)
            active = out.strip()
            if active != "active":
                rc2, out2, _ = self.run(["systemctl", "is-active", "sshd"], timeout=4)
                if out2.strip() == "active":
                    active = "active"
        cfg, source = self.ssh_effective_config()
        self.raw["ssh_config_source"] = source
        self.raw["ssh_effective_config"] = cfg

        if active != "active":
            self.add(section, "OK", "SSH ne semble pas actif", "Service ssh/sshd non actif selon systemctl.")
            return
        self.add(section, "INFO", "SSH actif", f"Configuration lue via: {source}")

        permit_root = cfg.get("permitrootlogin", "unknown")
        if permit_root in ("yes", "forced-commands-only"):
            self.add(section, "HIGH", "Connexion SSH root autorisée", f"PermitRootLogin={permit_root}", "Mettre : PermitRootLogin no")
        elif permit_root in ("prohibit-password", "without-password"):
            self.add(section, "LOW", "SSH root partiellement autorisé par clé", f"PermitRootLogin={permit_root}", "Pour durcissement fort : PermitRootLogin no")
        elif permit_root == "no":
            self.add(section, "OK", "SSH root désactivé", "PermitRootLogin no")
        else:
            self.add(section, "MEDIUM", "État PermitRootLogin non confirmé", f"PermitRootLogin={permit_root}")

        pwd_auth = cfg.get("passwordauthentication", "unknown")
        if pwd_auth == "yes":
            self.add(section, "HIGH", "Authentification SSH par mot de passe active", "PasswordAuthentication=yes", "Préférer clés SSH : PasswordAuthentication no, PubkeyAuthentication yes.")
        elif pwd_auth == "no":
            self.add(section, "OK", "Authentification SSH par mot de passe désactivée", "PasswordAuthentication=no")
        else:
            self.add(section, "MEDIUM", "État PasswordAuthentication non confirmé", f"PasswordAuthentication={pwd_auth}")

        pubkey = cfg.get("pubkeyauthentication", "unknown")
        if pubkey == "no":
            self.add(section, "MEDIUM", "Authentification par clé SSH désactivée", "PubkeyAuthentication=no", "Activer PubkeyAuthentication yes si SSH est nécessaire.")
        else:
            self.add(section, "OK", "Authentification par clé SSH possible", f"PubkeyAuthentication={pubkey}")

        port = cfg.get("port", "22")
        if port == "22":
            self.add(section, "LOW", "SSH sur le port standard 22", "Ce n'est pas une faille, mais augmente le bruit de scan si exposé.", "Limiter par pare-feu/VPN plutôt que compter sur un changement de port.")
        else:
            self.add(section, "INFO", "SSH sur port non standard", f"Port={port}")

        maxauth = cfg.get("maxauthtries")
        if maxauth and maxauth.isdigit() and int(maxauth) > 4:
            self.add(section, "LOW", "MaxAuthTries élevé", f"MaxAuthTries={maxauth}", "Mettre MaxAuthTries 3 ou 4.")
        x11 = cfg.get("x11forwarding")
        if x11 == "yes":
            self.add(section, "LOW", "X11Forwarding actif", "X11Forwarding=yes", "Désactiver si non utilisé : X11Forwarding no.")
        allowusers = cfg.get("allowusers")
        if not allowusers:
            self.add(section, "LOW", "Pas de restriction AllowUsers SSH", "Tous les comptes valides peuvent potentiellement tenter SSH.", "Ajouter AllowUsers <admin> si compatible avec ton exploitation.")

    def check_users(self):
        section = "Comptes"
        uid0 = []
        login_shell_users = []
        for u in pwd.getpwall():
            if u.pw_uid == 0:
                uid0.append(u.pw_name)
            if u.pw_shell and not re.search(r"nologin|false|sync|shutdown|halt", u.pw_shell):
                login_shell_users.append(f"{u.pw_name}:{u.pw_uid}:{u.pw_shell}")
        if uid0 == ["root"]:
            self.add(section, "OK", "Un seul compte UID 0", "root uniquement")
        else:
            self.add(section, "CRITICAL", "Plusieurs comptes UID 0 détectés", ", ".join(uid0), "Supprimer ou corriger immédiatement les comptes UID 0 non-root.")

        if any(line.startswith("pi:") for line in login_shell_users):
            self.add(section, "MEDIUM", "Compte par défaut 'pi' présent avec shell", "Le compte pi est très ciblé sur Raspberry.", "Renommer/désactiver pi si non nécessaire, imposer clé SSH et mot de passe robuste.")
        else:
            self.add(section, "OK", "Compte 'pi' non détecté avec shell interactif", "Bon point de durcissement Raspberry.")

        self.raw["interactive_users"] = login_shell_users
        self.add(section, "INFO", "Comptes interactifs", "\n".join(login_shell_users[:80]))

        sudo_members = []
        try:
            for group_name in ("sudo", "adm", "docker"):
                try:
                    g = grp.getgrnam(group_name)
                    if g.gr_mem:
                        sudo_members.append(f"{group_name}: {', '.join(g.gr_mem)}")
                except KeyError:
                    pass
        except Exception:
            pass
        if sudo_members:
            self.add(section, "INFO", "Groupes sensibles", "\n".join(sudo_members))
        if any(line.startswith("docker:") for line in sudo_members):
            self.add(section, "HIGH", "Utilisateurs dans le groupe docker", "Le groupe docker donne pratiquement des privilèges root.", "Limiter strictement l'accès au groupe docker.")

        shadow = self.read_text("/etc/shadow") if os.geteuid() == 0 else ""
        if shadow:
            empty = []
            unlocked_interactive = []
            shell_map = {u.pw_name: u.pw_shell for u in pwd.getpwall()}
            for line in shadow.splitlines():
                fields = line.split(":")
                if len(fields) < 2:
                    continue
                name, hashv = fields[0], fields[1]
                shell = shell_map.get(name, "")
                interactive = shell and not re.search(r"nologin|false|sync|shutdown|halt", shell)
                if hashv == "":
                    empty.append(name)
                if interactive and hashv and not hashv.startswith(("!", "*")):
                    unlocked_interactive.append(name)
            if empty:
                self.add(section, "CRITICAL", "Comptes sans mot de passe", ", ".join(empty), "Verrouiller immédiatement : passwd -l <user>")
            if unlocked_interactive:
                self.add(section, "INFO", "Comptes interactifs avec mot de passe local actif", ", ".join(unlocked_interactive), "À valider : privilégier clés SSH et mots de passe robustes.")

        sudoers = self.read_text("/etc/sudoers") + "\n" + "\n".join(self.read_text(f) for f in glob.glob("/etc/sudoers.d/*"))
        nopass = [l for l in sudoers.splitlines() if "NOPASSWD" in l and not l.strip().startswith("#")]
        if nopass:
            self.add(section, "HIGH", "Sudo NOPASSWD détecté", "\n".join(nopass[:20]), "Éviter NOPASSWD en production, sauf commande très limitée et justifiée.")

    def check_file_permissions(self):
        section = "Permissions"
        checks = [
            ("/etc/shadow", 0o640, "root"),
            ("/etc/passwd", 0o644, "root"),
            ("/etc/sudoers", 0o440, "root"),
            ("/etc/ssh/sshd_config", 0o644, "root"),
            ("/root", 0o700, "root"),
        ]
        for path, max_mode, owner in checks:
            p = Path(path)
            if not p.exists():
                continue
            try:
                st = p.stat()
                mode = stat.S_IMODE(st.st_mode)
                user = pwd.getpwuid(st.st_uid).pw_name
                if mode <= max_mode and user == owner:
                    self.add(section, "OK", f"Permissions correctes: {path}", f"mode={oct(mode)} owner={user}")
                else:
                    self.add(section, "HIGH", f"Permissions à corriger: {path}", f"mode={oct(mode)} owner={user}, attendu <= {oct(max_mode)} owner={owner}", f"Corriger avec chmod/chown sur {path}")
            except Exception as e:
                self.add(section, "LOW", f"Impossible de vérifier {path}", repr(e))

        # World writable dirs without sticky bit on same filesystem.
        rc, out, err = self.run("find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -100", timeout=15, shell=True)
        if out.strip():
            self.add(section, "HIGH", "Répertoires world-writable sans sticky bit", out, "Corriger les permissions ou supprimer ces répertoires.")
        else:
            self.add(section, "OK", "Aucun répertoire world-writable dangereux détecté", "Recherche limitée au filesystem racine.")

    def check_sysctl(self):
        section = "Durcissement noyau/sysctl"
        checks = [
            ("/proc/sys/kernel/randomize_va_space", "2", "ASLR complet"),
            ("/proc/sys/kernel/kptr_restrict", "1", "Masquage pointeurs noyau"),
            ("/proc/sys/kernel/dmesg_restrict", "1", "Restriction dmesg"),
            ("/proc/sys/fs/protected_hardlinks", "1", "Protection hardlinks"),
            ("/proc/sys/fs/protected_symlinks", "1", "Protection symlinks"),
            ("/proc/sys/net/ipv4/tcp_syncookies", "1", "SYN cookies"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0", "ICMP redirects IPv4 refusés"),
            ("/proc/sys/net/ipv4/conf/default/accept_redirects", "0", "ICMP redirects IPv4 default refusés"),
            ("/proc/sys/net/ipv4/conf/all/accept_source_route", "0", "Source route IPv4 refusé"),
            ("/proc/sys/net/ipv4/conf/default/accept_source_route", "0", "Source route IPv4 default refusé"),
            ("/proc/sys/net/ipv4/conf/all/send_redirects", "0", "Envoi redirects IPv4 désactivé"),
            ("/proc/sys/net/ipv4/conf/default/send_redirects", "0", "Envoi redirects IPv4 default désactivé"),
        ]
        for path, expected, label in checks:
            val = self.read_text(path, 32).strip()
            if val == "":
                continue
            if val == expected:
                self.add(section, "OK", label, f"{path}={val}")
            else:
                sev = "MEDIUM" if "redirect" in path or "source_route" in path else "LOW"
                self.add(section, sev, f"Paramètre à durcir: {label}", f"{path}={val}, attendu={expected}", "Ajouter dans /etc/sysctl.d/99-avhiral-hardening.conf puis sysctl --system")

        ipf = self.read_text("/proc/sys/net/ipv4/ip_forward", 32).strip()
        if ipf == "1":
            self.add(section, "INFO", "IPv4 forwarding activé", "Normal si le Raspberry sert de passerelle/bridge/routeur. Sinon à désactiver.")
        elif ipf == "0":
            self.add(section, "OK", "IPv4 forwarding désactivé", "Le Pi ne route pas le trafic IPv4.")
        v6f = self.read_text("/proc/sys/net/ipv6/conf/all/forwarding", 32).strip()
        if v6f == "1":
            self.add(section, "INFO", "IPv6 forwarding activé", "Normal uniquement si le Pi route IPv6.")

        bpf = self.read_text("/proc/sys/kernel/unprivileged_bpf_disabled", 32).strip()
        if bpf:
            if bpf in ("1", "2"):
                self.add(section, "OK", "BPF non privilégié désactivé/restreint", f"unprivileged_bpf_disabled={bpf}")
            else:
                self.add(section, "LOW", "BPF non privilégié autorisé", f"unprivileged_bpf_disabled={bpf}", "Désactiver si compatible : kernel.unprivileged_bpf_disabled=1")

    def check_services(self):
        section = "Services"
        if not self.exists_cmd("systemctl"):
            self.add(section, "INFO", "systemctl non disponible", "Impossible de lister les services systemd.")
            return
        rc, out, err = self.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"], timeout=12)
        if rc != 0:
            self.add(section, "LOW", "Impossible de lister les services actifs", err or out)
            return
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        self.raw["running_services"] = lines[:200]
        self.add(section, "INFO", "Services actifs", "\n".join(lines[:80]))
        hits = []
        for line in lines:
            lname = line.lower()
            for svc in HIGH_RISK_SERVICES:
                if svc in lname:
                    hits.append(line)
                    break
        if hits:
            self.add(section, "MEDIUM", "Services à valider/désactiver si inutiles", "\n".join(hits[:40]), "Réduire la surface : systemctl disable --now <service>")
        else:
            self.add(section, "OK", "Aucun service sensible courant détecté", "Selon la liste intégrée.")

        for svc in ("fail2ban", "auditd", "nftables", "dnsmasq", "ssh"):
            rc, active, _ = self.run(["systemctl", "is-active", svc], timeout=4)
            rc2, enabled, _ = self.run(["systemctl", "is-enabled", svc], timeout=4)
            self.add(section, "INFO", f"État service {svc}", f"active={active or 'unknown'} enabled={enabled or 'unknown'}")

        rc, out, _ = self.run(["systemctl", "is-active", "fail2ban"], timeout=4)
        if out.strip() == "active":
            self.add(section, "OK", "Fail2ban actif", "Protection bruteforce active si jail SSH configuré.")
        else:
            self.add(section, "MEDIUM", "Fail2ban inactif ou absent", "Recommandé si SSH est actif.", "Installer/configurer : apt install fail2ban")

    def check_logs(self):
        section = "Journaux / attaques"
        if self.exists_cmd("journalctl"):
            rc, out, _ = self.run(["journalctl", "--since", "24 hours ago", "--no-pager"], timeout=18)
            if rc == 0 and out:
                failed = len(re.findall(r"Failed password|authentication failure|Invalid user|Connection closed by authenticating user", out, re.I))
                sudo = len(re.findall(r"sudo:.*authentication failure|incorrect password", out, re.I))
                oom = len(re.findall(r"Out of memory|oom-killer", out, re.I))
                if failed > 50:
                    self.add(section, "HIGH", f"Nombre élevé d'échecs SSH/auth en 24h: {failed}", "Le Pi subit probablement des tentatives de bruteforce.", "Activer Fail2ban, désactiver PasswordAuthentication, limiter SSH au LAN/VPN.")
                elif failed > 0:
                    self.add(section, "LOW", f"Échecs SSH/auth en 24h: {failed}", "À surveiller.")
                else:
                    self.add(section, "OK", "Aucun échec SSH/auth massif en 24h", "Selon journalctl.")
                if sudo:
                    self.add(section, "MEDIUM", f"Échecs sudo détectés: {sudo}", "Vérifier les tentatives locales.")
                if oom:
                    self.add(section, "MEDIUM", f"Événements OOM détectés: {oom}", "Peut indiquer surcharge ou attaque DoS locale.")
            else:
                self.add(section, "INFO", "journalctl indisponible ou vide", "Impossible d'analyser les journaux récents.")
        else:
            self.add(section, "INFO", "journalctl absent", "Analyse des journaux limitée.")

    def check_integrity_indicators(self):
        section = "Indicateurs d'intégrité"
        # Deleted executable processes
        deleted = []
        for exe in glob.glob("/proc/[0-9]/exe"):
            try:
                target = os.readlink(exe)
                if "(deleted)" in target:
                    pid = exe.split("/")[2]
                    cmdline = self.read_text(f"/proc/{pid}/cmdline", 4096).replace("\x00", " ").strip()
                    deleted.append(f"pid={pid} exe={target} cmd={cmdline}")
            except Exception:
                continue
        if deleted:
            self.add(section, "HIGH", "Processus exécutant un binaire supprimé", "\n".join(deleted[:40]), "Analyser immédiatement : ps aux, lsof, redémarrage contrôlé, investigation.")
        else:
            self.add(section, "OK", "Aucun processus avec binaire supprimé détecté", "Bon signe d'intégrité runtime.")

        # SUID files
        rc, out, err = self.run("find / -xdev -perm -4000 -type f -printf '%p\n' 2>/dev/null", timeout=25, shell=True)
        if rc == 0:
            files = [l for l in out.splitlines() if l]
            self.raw["suid_files"] = files
            unusual = [f for f in files if not re.match(r"^/(usr/)?(bin|sbin|lib|libexec)/", f)]
            self.add(section, "INFO", f"Fichiers SUID détectés: {len(files)}", "\n".join(files[:80]))
            if unusual:
                self.add(section, "HIGH", "Fichiers SUID inhabituels", "\n".join(unusual[:40]), "Vérifier l'origine des fichiers. Supprimer le bit SUID si non justifié : chmod u-s <fichier>")
        else:
            self.add(section, "LOW", "Impossible de lister les fichiers SUID", err)

        # /tmp executable scripts/binaries, shallow check
        tmp_hits = []
        for base in ("/tmp", "/var/tmp", "/dev/shm"):
            for p in glob.glob(base + "/**", recursive=True):
                try:
                    st = os.stat(p)
                    if stat.S_ISREG(st.st_mode) and (st.st_mode & 0o111):
                        tmp_hits.append(p)
                        if len(tmp_hits) >= 50:
                            break
                except Exception:
                    pass
            if len(tmp_hits) >= 50:
                break
        if tmp_hits:
            self.add(section, "MEDIUM", "Fichiers exécutables dans /tmp/var/tmp/dev/shm", "\n".join(tmp_hits[:50]), "À valider : les malwares utilisent souvent ces chemins.")
        else:
            self.add(section, "OK", "Pas d'exécutables évidents dans les répertoires temporaires", "Recherche récursive limitée.")

    def check_avhiral_streamguard(self):
        section = "AVHIRAL StreamGuard"
        root = Path("/root/avhiral-streamguard-ai")
        if not root.exists():
            self.add(section, "INFO", "Dossier StreamGuard non trouvé", "/root/avhiral-streamguard-ai absent.")
            return
        self.add(section, "OK", "Dossier StreamGuard trouvé", str(root))

        script = root / "avhiral-streamguard-ai.py"
        if script.exists():
            st = script.stat()
            self.add(section, "INFO", "Script principal présent", f"{script} mode={oct(stat.S_IMODE(st.st_mode))} size={st.st_size}")
        else:
            self.add(section, "HIGH", "Script principal absent", str(script))

        rc, out, _ = self.run(["pgrep", "-af", "avhiral-streamguard-ai.py"], timeout=4)
        if rc == 0 and out.strip():
            self.add(section, "OK", "Processus StreamGuard actif", out)
        else:
            self.add(section, "LOW", "Processus StreamGuard non détecté", "Normal si le service est volontairement arrêté.")

        dns_conf = Path("/etc/dnsmasq.d/avhiral-streamguard-ai.conf")
        if dns_conf.exists():
            txt = self.read_text(str(dns_conf), 20000)
            self.add(section, "OK", "Configuration dnsmasq StreamGuard présente", txt[:2000])
        else:
            self.add(section, "LOW", "Configuration dnsmasq StreamGuard absente", "Le blocage DNS peut ne pas être actif.")

        if self.exists_cmd("nft"):
            rc, out, _ = self.run(["nft", "list", "ruleset"], timeout=8)
            if "avhiral_streamguard_ai" in out:
                self.add(section, "OK", "Règles nftables AVHIRAL présentes", "Tables avhiral_streamguard_ai détectées.")
            else:
                self.add(section, "LOW", "Règles nftables AVHIRAL non détectées", "Le filtrage peut ne pas être appliqué.")

        # Config sanity
        for conf in (root / "config" / "deny_endpoints.txt", root / "config" / "deny_domains.txt", root / "config" / "deny_ports.txt"):
            if conf.exists():
                lines = [l.strip() for l in self.read_text(str(conf)).splitlines() if l.strip() and not l.strip().startswith("#")]
                self.add(section, "INFO", f"{conf.name}: {len(lines)} entrée(s)", "\n".join(lines[:80]))

    def check_network_config(self):
        section = "Configuration réseau"
        for cmd in (["ip", "-br", "addr"], ["ip", "route"], ["resolvectl", "status"]):
            if self.exists_cmd(cmd[0]):
                rc, out, err = self.run(cmd, timeout=6)
                if rc == 0 and out:
                    self.add(section, "INFO", " ".join(cmd), out[:4000])
        resolv = self.read_text("/etc/resolv.conf")
        if resolv:
            self.add(section, "INFO", "/etc/resolv.conf", resolv)
            if "127.0.0.1" in resolv or "127.0.0.53" in resolv:
                self.add(section, "OK", "Résolution DNS locale détectée", "Le Pi utilise un resolver local/systemd-resolved/dnsmasq.")
        hosts_allow = self.read_text("/etc/hosts.allow")
        hosts_deny = self.read_text("/etc/hosts.deny")
        if hosts_allow.strip() or hosts_deny.strip():
            self.add(section, "INFO", "tcp_wrappers configuré", f"hosts.allow:\n{hosts_allow}\nhosts.deny:\n{hosts_deny}")

    def run_all(self):
        self.collect_system_info()
        self.check_network_config()
        self.check_updates()
        self.check_listening_ports()
        self.check_firewall()
        self.check_ssh()
        self.check_users()
        self.check_file_permissions()
        self.check_sysctl()
        self.check_services()
        self.check_logs()
        self.check_integrity_indicators()
        self.check_avhiral_streamguard()

    def score(self):
        score = 100
        for f in self.findings:
            score -= SEVERITY_PENALTY.get(f.severity, 0)
        return max(0, min(100, score))

    def grade(self):
        s = self.score()
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 65:
            return "C"
        if s >= 50:
            return "D"
        return "E"

    def summary_counts(self):
        counts = {k: 0 for k in SEVERITY_ORDER.keys()}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def report_obj(self):
        return {
            "tool": APP_NAME,
            "version": VERSION,
            "hostname": self.hostname,
            "timestamp": self.now.isoformat(),
            "duration_seconds": round(time.time() - self.started, 2),
            "score": self.score(),
            "grade": self.grade(),
            "counts": self.summary_counts(),
            "findings": [f.as_dict() for f in sorted(self.findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.section, x.title))],
            "raw": self.raw,
        }

    def save_reports(self):
        ts = self.now.strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"diagnosticPi4_report_{ts}.json"
        txt_path = self.output_dir / f"diagnosticPi4_report_{ts}.txt"
        obj = self.report_obj()
        json_path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        txt_path.write_text(self.render_text(Colors(False)), encoding="utf-8")
        return txt_path, json_path

    def render_text(self, c):
        obj = self.report_obj()
        lines = []
        lines.append(f"{APP_NAME} v{VERSION}")
        lines.append("=" * 72)
        lines.append(f"Hôte      : {obj['hostname']}")
        lines.append(f"Date      : {obj['timestamp']}")
        lines.append(f"Score     : {obj['score']}/100   Grade: {obj['grade']}")
        lines.append(f"Durée     : {obj['duration_seconds']}s")
        counts = obj["counts"]
        lines.append("Synthèse  : " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
        lines.append("")

        critical_or_high = [f for f in obj["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
        if critical_or_high:
            lines.append("ACTIONS PRIORITAIRES")
            lines.append("-" * 72)
            for f in critical_or_high:
                lines.append(f"[{f['severity']}] {f['section']} - {f['title']}")
                if f["detail"]:
                    lines.append(indent(f["detail"], "  "))
                if f["remediation"]:
                    lines.append("  Correction: " + f["remediation"].replace("\n", "\n              "))
                lines.append("")
        else:
            lines.append("ACTIONS PRIORITAIRES")
            lines.append("-" * 72)
            lines.append("Aucune alerte CRITICAL/HIGH détectée par ce diagnostic local.")
            lines.append("")

        current_section = None
        lines.append("DÉTAIL COMPLET")
        lines.append("-" * 72)
        for f in obj["findings"]:
            if f["section"] != current_section:
                current_section = f["section"]
                lines.append("")
                lines.append(f"## {current_section}")
            lines.append(f"[{f['severity']}] {f['title']}")
            if f["detail"]:
                lines.append(indent(f["detail"], "  "))
            if f["remediation"]:
                lines.append("  Correction: " + f["remediation"].replace("\n", "\n              "))
        lines.append("")
        lines.append("Note: ce diagnostic est local et défensif. Il ne remplace pas un audit de configuration complet, un test d'intrusion encadré, ni une revue de code.")
        return "\n".join(lines)

    def print_console(self, color=True):
        c = Colors(color)
        obj = self.report_obj()
        print(f"{c.bold}{APP_NAME} v{VERSION}{c.reset}")
        print("=" * 72)
        print(f"Hôte  : {obj['hostname']}")
        print(f"Date  : {obj['timestamp']}")
        score = obj["score"]
        grade = obj["grade"]
        score_color = c.green if score >= 80 else c.yellow if score >= 65 else c.red
        print(f"Score : {score_color}{score}/100 - Grade {grade}{c.reset}")
        counts = obj["counts"]
        print("Alertes : " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))
        print()

        priority = [f for f in obj["findings"] if f["severity"] in ("CRITICAL", "HIGH")]
        print(f"{c.bold}ACTIONS PRIORITAIRES{c.reset}")
        print("-" * 72)
        if not priority:
            print(f"{c.green}[OK]{c.reset} Aucune alerte CRITICAL/HIGH détectée par ce diagnostic local.")
        for f in priority:
            print(f"{c.sev(f['severity'])} {c.bold}{f['section']} - {f['title']}{c.reset}")
            if f["detail"]:
                print(indent(f["detail"], "  "))
            if f["remediation"]:
                print(f"  {c.cyan}Correction:{c.reset} {f['remediation']}")
            print()

        print(f"\n{c.bold}DÉTAIL COMPLET{c.reset}")
        print("-" * 72)
        current = None
        for f in obj["findings"]:
            if f["section"] != current:
                current = f["section"]
                print(f"\n{c.bold}## {current}{c.reset}")
            print(f"{c.sev(f['severity'])} {f['title']}")
            if f["detail"]:
                print(indent(f["detail"], "  "))
            if f["remediation"]:
                print(f"  {c.cyan}Correction:{c.reset} {f['remediation']}")


def indent(text, prefix):
    if not text:
        return ""
    return "\n".join(prefix + line for line in str(text).splitlines())


def main():
    ap = argparse.ArgumentParser(description="Audit défensif local Raspberry Pi 4 - AVHIRAL diagnosticPi4")
    ap.add_argument("--output-dir", default=".", help="Dossier de sortie des rapports TXT/JSON, défaut: dossier courant")
    ap.add_argument("--no-color", action="store_true", help="Désactive les couleurs ANSI")
    ap.add_argument("--json-only", action="store_true", help="Affiche uniquement le JSON sur stdout")
    args = ap.parse_args()

    auditor = Auditor(args)
    auditor.run_all()

    if args.json_only:
        print(json.dumps(auditor.report_obj(), ensure_ascii=False, indent=2))
        return

    auditor.print_console(color=(not args.no_color and sys.stdout.isatty()))
    txt_path, json_path = auditor.save_reports()
    print("\nRapports générés :")
    print(f"- TXT  : {txt_path}")
    print(f"- JSON : {json_path}")
    print("\nCommande conseillée : sudo python3 diagnosticPi4.py --output-dir /root")


if __name__ == "__main__":
    main()
