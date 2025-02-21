from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLineEdit, QHBoxLayout, QCheckBox
)
from PyQt6.QtCore import Qt

from external_process_thread import ExternalProcessThread

class NmapPanel(QWidget):
    """
    Nmap with categories in a QTreeWidget.
    Each category has child scans with parentheses for flags.
    """
    def __init__(self, parent_main):
        super().__init__()
        self.parent_main = parent_main
        self.process_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.setLayout(layout)

        # A QTreeWidget for categories
        self.nmap_tree = QTreeWidget()
        self.nmap_tree.setHeaderHidden(True)
        layout.addWidget(self.nmap_tree)

        # Build categories -> list of (scan_name, tooltip_text)
        categories = {
            "Host Discovery": [
                ("Ping Scan (-sn)", "No port scan, discover live hosts."),
                ("List Scan (-sL)", "Lists targets without sending real probes.")
            ],
            "Basic / Common": [
                ("Quick Scan (-T4 -F)", "Fast scan top 100 ports."),
                ("Full Port Scan (-p-)", "Scan all 65535 TCP ports."),
                ("Default Scripts (-sC)", "Default safe NSE scripts."),
                ("TCP Connect Scan (-sT)", "Full TCP handshake."),
                ("Stealth SYN Scan (-sS)", "Half-open SYN approach."),
            ],
            "Service / OS Detection": [
                ("Service/OS Detect (-A)", "OS detect, version detection, default scripts, traceroute."),
                ("Version Detection (-sV)", "Identify service versions on open ports.")
            ],
            "Advanced / Stealth": [
                ("Null Scan (-sN)", "No TCP flags set."),
                ("Fin Scan (-sF)", "Only FIN flag."),
                ("Xmas Scan (-sX)", "FIN, PSH, URG set."),
                ("ACK Scan (-sA)", "Distinguish filtered vs unfiltered."),
                ("IP Protocol Scan (-sO)", "Check which IP protocols are supported."),
                ("Fragmentation Scan (-f)", "Send fragmented packets."),
                ("Decoy Scan (-D RND:10)", "Use random decoys to mask real IP."),
            ],
            "Comprehensive / Aggressive": [
                ("Aggressive+OS+Scripts (-T4 -A -O)", "Combines OS detect, version, default scripts, T4 timing."),
                ("Comprehensive (-p- -A)", "All TCP ports plus OS detect, default scripts."),
                ("Slow Comprehensive (--scan-delay 1s -sS -p- -A)",
                 "Comprehensive but slower to avoid detection."),
                ("Top Ports + Vuln (--top-ports 200 -sV --script=vulners)",
                 "Scan top 200 ports plus vulnerability checks.")
            ],
            "UDP / IP Protocol": [
                ("UDP Scan (-sU)", "Scans UDP ports, slower but important."),
                ("IP Protocol Scan (-sO)", "Which IP protocols (ICMP, TCP, etc.) are supported?"),
            ],
            "NSE Script-Based": [
                ("HTTP Enum & Title (--script=http-enum,http-title)",
                 "Enumerate web paths, retrieve page titles."),
                ("SSL Analysis (--script=ssl-enum-ciphers,ssl-cert -p443)",
                 "Check SSL/TLS ciphers & cert info on 443."),
                ("SMB Shares & Users (--script=smb-enum-shares,smb-enum-users -p445)",
                 "Enumerate Windows shares & user accounts."),
                ("DNS Bruteforce (--script=dns-brute)",
                 "Brute force subdomains."),
                ("Vulners & Version Detect (--script=vulners -sV)",
                 "Check known CVEs + version detection."),
                ("FTP Anonymous (--script=ftp-anon -p21)",
                 "Check if FTP allows anonymous login."),
                ("HTTP robots.txt (--script=http-robots.txt -p80,443)",
                 "Retrieve /robots.txt for hidden paths."),
                ("MySQL Empty Password (--script=mysql-empty-password -p3306)",
                 "Check if MySQL root has empty password."),
            ]
        }

        for cat_name, scans in categories.items():
            cat_item = QTreeWidgetItem([cat_name])
            cat_item.setExpanded(True)  # expand by default
            self.nmap_tree.addTopLevelItem(cat_item)
            for (scan_text, tip) in scans:
                child_item = QTreeWidgetItem([scan_text])
                child_item.setToolTip(0, tip)
                cat_item.addChild(child_item)

        # Stats checkbox
        self.cb_stats = QCheckBox("Show Progress Stats (10s)")
        layout.addWidget(self.cb_stats)

        # Buttons row
        btn_layout = QHBoxLayout()
        layout.addLayout(btn_layout)

        self.btn_run = QPushButton("Run Selected")
        self.btn_run.clicked.connect(self.run_selected)
        btn_layout.addWidget(self.btn_run)

        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.clicked.connect(self.stop_scan)
        btn_layout.addWidget(self.btn_stop)

    def run_selected(self):
        """Check if a child (scan) is selected. If top-level category is selected, no run."""
        selected_item = self.nmap_tree.currentItem()
        if not selected_item:
            self.parent_main.log_nmap("No Nmap scan selected.")
            return

        # If there's no parent, it's a category, not a scan
        if not selected_item.parent():
            self.parent_main.log_nmap("Please expand a category and select a specific scan.")
            return

        text = selected_item.text(0)
        # parse parentheses
        options_part = ""
        if "(" in text and ")" in text:
            options_part = text.split("(")[-1].split(")")[0].strip()

        target = self.parent_main.get_global_target()
        if not target:
            self.parent_main.log_nmap("Please enter a target in the global box.")
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
        self.parent_main.log_nmap(f"[+] Nmap finished (exit code {exit_code}).\n")
        self.process_thread = None

    def stop_scan(self):
        if self.process_thread:
            self.parent_main.log_nmap("[*] Stopping Nmap scan...")
            self.process_thread.stop()
            self.process_thread = None
        else:
            self.parent_main.log_nmap("No Nmap scan is running.")
