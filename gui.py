# In gui.py (MainWindow setup pseudocode)
self.nmapOutput = QPlainTextEdit()
self.nmapOutput.setReadOnly(True)
# ... similarly for bettercapOutput
# Connect signals:
self.nmapScanner = None  # will be created when scan starts
self.startScanButton.clicked.connect(self.on_start_scan)
# ...
def on_start_scan(self):
    target = self.targetInput.text()
    opts = self.buildNmapOptionsFromUI()  # gather chosen scan flags
    if target:
        self.nmapScanner = NmapScanner(target, opts)
        self.nmapScanner.output_signal.connect(self.append_nmap_log)
        self.nmapScanner.finished_signal.connect(self.on_scan_finished)
        self.nmapScanner.start()

def append_nmap_log(self, text_line):
    # Append text to Nmap log box
    self.nmapOutput.appendPlainText(text_line)

def on_scan_finished(self, code):
    self.append_nmap_log(f"\nScan completed (exit code {code}).")

# Similar connections for Bettercap:
self.bettercapSession = BettercapSession(interface=self.interfaceDropdown.currentText())
self.bettercapSession.log_signal.connect(self.append_bettercap_log)
# On clicking "Start Bettercap":
self.bettercapSession.start()
# On toggling a module, e.g., ARP Spoof checkbox:
if self.arpSpoofCheck.isChecked():
    self.bettercapSession.send_command("arp.spoof on")
else:
    self.bettercapSession.send_command("arp.spoof off")
