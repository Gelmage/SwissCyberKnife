from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QHBoxLayout,
    QListWidgetItem, QCheckBox
)
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class NmapPanel(QWidget):
    """
    Large set of Nmap scans (basic, advanced, script-based) with tooltips.
    Will read target/ports from main_window.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.process_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        self.nmap_list = QListWidget()
        layout.addWidget(self.nmap_list)

        # Combine basic, advanced, script-based
        scans_data = [
            # Basic
            ("Ping Scan (-sn)", "Discovers live hosts without port scanning."),
            ("Quick Scan (-T4 -F)", "Fast scan top 100 ports."),
            ("Full Port Scan (-p-)", "All 65535 TCP ports."),
            ("Service/OS Detect (-A)", "OS detection, version detection, scripts, traceroute."),
            ("UDP Scan (-sU)", "Scans UDP ports (slower)."),
            ("TCP Connect Scan (-sT)", "Full TCP handshake scan."),
            ("Stealth SYN Scan (-sS)", "SYN only, doesn't complete handshake."),
            ("Version Detection (-sV)", "Detect service versions on open ports."),
            ("List Scan (-sL)", "List targets, no actual probes."),
            ("Default Scripts (-sC)", "Run default safe NSE scripts."),

            # Advanced
            ("Null Scan (-sN)", "No TCP flags, can bypass some firewalls."),
            ("Fin Scan (-sF)", "Only FIN flag set."),
            ("Xmas Scan (-sX)", "FIN, PSH, URG set (Xmas tree)."),
            ("ACK Scan (-sA)", "Distinguish filtered vs. unfiltered ports."),
            ("IP Protocol Scan (-sO)", "Check which IP protocols (ICMP, TCP, etc.) are supported."),
            ("Fragmentation Scan (-f)", "Send tiny fragmented packets."),
            ("Aggressive+OS+Scripts (-T4 -A -O)", "OS detect, version, default scripts, timing T4."),
            ("Decoy Scan (-D RND:10)", "Use random decoy IPs to mask real source."),
            ("Comprehensive (-p- -A)", "All TCP ports + OS detect + default scripts."),
            ("Slow Comprehensive (--scan-delay 1s -sS -p- -A)",
             "Comprehensive but slower to avoid detection."),

            # Script-based
            ("HTTP Enum & Title (--script=http-enum,http-title)", "Enumerate web paths + page titles."),
            ("SSL Analysis (--script=ssl-enum-ciphers,ssl-cert -p443)",
             "Check SSL/TLS ciphers & certificate info on 443."),
            ("SMB Shares & Users (--script=smb-enum-shares,smb-enum-users -p445)",
             "Enumerate Windows shares & user accounts on port 445."),
            ("DNS Bruteforce (--script=dns-brute)", "Brute force subdomains with DNS."),
            ("Vulners & Version Detect (--script=vulners -sV)",
             "Check known CVEs with 'vulners' script + version detection."),
            ("FTP Anonymous (--script=ftp-anon -p21)", "Check if FTP allows anonymous logins."),
            ("HTTP robots.txt (--script=http-robots.txt -p80,443)",
             "Retrieve /robots.txt for hidden paths."),
            ("MySQL Empty Password (--script=mysql-empty-password -p3306)",
             "Check if MySQL root has empty password."),
            ("Top Ports + Vuln (--top-ports 200 -sV --script=vulners)",
             "Scan top 200 ports + vulnerability checks.")
        ]

        for display_text, tip in scans_data:
            item = QListWidgetItem(display_text)
            item.setToolTip(tip)
            self.nmap_list.addItem(item)

        self.cb_stats = QCheckBox("Show Progress Stats (10s)")
        layout.addWidget(self.cb_stats)

        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Scan")
        self.btn_run.clicked.connect(self.run_selected)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.btn_stop)

    def run_selected(self):
        item = self.nmap_list.currentItem()
        if not item:
            self.parent_main.log_nmap("Please select an Nmap scan.")
            return

        text = item.text()
        options_part = ""
        if "(" in text and ")" in text:
            options_part = text.split("(")[-1].split(")")[0].strip()

        target = self.parent_main.get_global_target()
        if not target:
            self.parent_main.log_nmap("No target specified in global box.")
            return

        ports = self.parent_main.get_global_ports()

        cmd_list = ["nmap"]
        if self.cb_stats.isChecked():
            cmd_list.extend(["--stats-every", "10s"])

        if options_part:
            cmd_list.extend(options_part.split())

        cmd_list.append(target)

        if ports:
            cmd_list.extend(["-p", ports])

        cmd_str = " ".join(cmd_list)
        self.parent_main.log_nmap(f"[*] Running: {cmd_str}")

        self.process_thread = ExternalProcessThread(cmd_list)
        self.process_thread.output_signal.connect(self.parent_main.log_nmap)
        self.process_thread.finished_signal.connect(self.on_nmap_finished)
        self.process_thread.start()

    def on_nmap_finished(self, exit_code):
        self.parent_main.log_nmap(f"[+] Nmap scan finished (exit code {exit_code}).\n")
        self.process_thread = None

    def stop_scan(self):
        if self.process_thread:
            self.parent_main.log_nmap("[*] Stopping Nmap scan...")
            self.process_thread.stop()
            self.process_thread = None
        else:
            self.parent_main.log_nmap("No Nmap scan is running.")
