"""
Real WiFi Network Scanner and Security Analyzer.
Detects connected WiFi and analyzes security level.
"""

import subprocess
import re
import json
from pathlib import Path
import platform
import urllib.request

class WiFiScanner:
    """Scan and analyze WiFi networks on the system."""
    
    def __init__(self):
        self.os_type = platform.system()
        self.wifi_data = {
            'ssid': 'Unknown',
            'signal_strength': 0,
            'encryption': 'Unknown',
            'security_level': 0,
            'status': 'Disconnected',
            'ip_address': 'N/A',
            'gateway': 'N/A',
            'dns': 'N/A',
            'channel': 'N/A',
            'frequency': 'N/A',
            'band': 'N/A',
            'protection_score': 0,
            'vulnerabilities': [],
            'recommendations': [],
            'vpn_server': 'Direct Connection',
            'vpn_protocol': 'None',
            'vpn_status': 'Disconnected'
        }
    
    def get_wifi_info_windows(self):
        """Get WiFi info on Windows using netsh."""
        try:
            # Get connected WiFi SSID
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interface'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract SSID
                ssid_match = re.search(r'SSID\s*:\s*(\S.*?)$', output, re.MULTILINE)
                if ssid_match:
                    ssid = ssid_match.group(1).strip()
                    if ssid and ssid != '':
                        self.wifi_data['ssid'] = ssid
                
                # Extract Signal Quality
                signal_match = re.search(r'Signal\s*:\s*(\d+)%', output)
                if signal_match:
                    self.wifi_data['signal_strength'] = int(signal_match.group(1))
                
                # Extract State
                state_match = re.search(r'State\s*:\s*(\S.*?)$', output, re.MULTILINE)
                if state_match:
                    state = state_match.group(1).strip()
                    self.wifi_data['status'] = 'Connected' if 'connected' in state.lower() else 'Disconnected'
            
            # Get security info
            if self.wifi_data['ssid'] and self.wifi_data['ssid'] != 'Unknown':
                try:
                    result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profiles', 'name=' + self.wifi_data['ssid'], 'key=clear'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        output = result.stdout
                        
                        # Extract Security Type
                        security_match = re.search(r'Authentication\s*:\s*(\S.*?)$', output, re.MULTILINE)
                        if security_match:
                            auth = security_match.group(1).strip()
                            self.wifi_data['encryption'] = auth
                        
                        # Extract Cipher
                        cipher_match = re.search(r'Cipher\s*:\s*(\S.*?)$', output, re.MULTILINE)
                        if cipher_match:
                            cipher = cipher_match.group(1).strip()
                            self.wifi_data['encryption'] += f" ({cipher})"
                except Exception as e:
                    print(f"Error getting security info: {e}")
        
        except Exception as e:
            print(f"Error getting WiFi info on Windows: {e}")
        
        # Check for VPN connection
        self.detect_vpn_connection()
    
    def get_wifi_info_linux(self):
        """Get WiFi info on Linux using nmcli or iwconfig."""
        try:
            # Try nmcli first
            result = subprocess.run(
                ['nmcli', 'device', 'wifi', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract SSID
                ssid_match = re.search(r'SSID:\s*(\S.*?)$', output, re.MULTILINE)
                if ssid_match:
                    self.wifi_data['ssid'] = ssid_match.group(1).strip()
                
                # Extract Signal
                signal_match = re.search(r'SIGNAL:\s*(\d+)', output)
                if signal_match:
                    self.wifi_data['signal_strength'] = int(signal_match.group(1))
                
                # Extract Security
                security_match = re.search(r'SECURITY:\s*(\S.*?)$', output, re.MULTILINE)
                if security_match:
                    self.wifi_data['encryption'] = security_match.group(1).strip()
                
                self.wifi_data['status'] = 'Connected'
        
        except Exception as e:
            print(f"Error getting WiFi info on Linux: {e}")
    
    def get_wifi_info_mac(self):
        """Get WiFi info on macOS."""
        try:
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract SSID
                ssid_match = re.search(r'SSID:\s*(\S.*?)$', output, re.MULTILINE)
                if ssid_match:
                    self.wifi_data['ssid'] = ssid_match.group(1).strip()
                
                # Extract RSSI (Signal)
                rssi_match = re.search(r'RSSI:\s*(-\d+)', output)
                if rssi_match:
                    rssi = int(rssi_match.group(1))
                    # Convert RSSI to percentage (roughly -30 to -90 dBm)
                    signal = max(0, min(100, (rssi + 90) * 2))
                    self.wifi_data['signal_strength'] = signal
                
                self.wifi_data['status'] = 'Connected'
        
        except Exception as e:
            print(f"Error getting WiFi info on macOS: {e}")
    
    def analyze_security(self):
        """Analyze WiFi security and calculate protection score."""
        encryption = self.wifi_data['encryption'].upper()
        signal = self.wifi_data['signal_strength']
        
        # Initialize score
        score = 0
        vulnerabilities = []
        recommendations = []
        
        # Check encryption type
        if 'WPA3' in encryption:
            score += 40
            self.wifi_data['encryption'] = 'WPA3'
        elif 'WPA2' in encryption:
            score += 30
            self.wifi_data['encryption'] = 'WPA2'
            recommendations.append('Consider upgrading to WPA3 for better security')
        elif 'WPA' in encryption:
            score += 20
            self.wifi_data['encryption'] = 'WPA'
            vulnerabilities.append('WPA is outdated, use WPA2 or WPA3')
            recommendations.append('Upgrade to WPA2 or WPA3 immediately')
        elif 'OPEN' in encryption or 'NONE' in encryption:
            score += 0
            self.wifi_data['encryption'] = 'Open (No Encryption)'
            vulnerabilities.append('Network is completely unencrypted')
            recommendations.append('Enable WPA2 or WPA3 encryption immediately')
        else:
            score += 10
            vulnerabilities.append('Unknown encryption type')
        
        # Check signal strength
        if signal >= 80:
            score += 15
        elif signal >= 60:
            score += 10
        elif signal >= 40:
            score += 5
            recommendations.append('Signal strength is weak, move closer to router')
        else:
            vulnerabilities.append('Very weak signal - vulnerable to attacks')
            recommendations.append('Improve WiFi signal strength')
        
        # Check SSID visibility
        if self.wifi_data['ssid'] == 'Unknown':
            vulnerabilities.append('Could not detect SSID')
            recommendations.append('Ensure WiFi is properly configured')
        else:
            score += 10
        
        # Additional security checks
        if 'CCMP' in encryption or 'AES' in encryption:
            score += 15
        elif 'TKIP' in encryption:
            vulnerabilities.append('TKIP cipher is weak')
            recommendations.append('Use CCMP/AES cipher instead')
        
        # Cap score at 100
        score = min(100, score)
        
        self.wifi_data['protection_score'] = score
        self.wifi_data['vulnerabilities'] = vulnerabilities
        self.wifi_data['recommendations'] = recommendations
        
        return score
    
    def _analyze_vpn_adapter_block(self, header_line, block_lines):
        block_text = "\n".join(block_lines)
        lower_text = block_text.lower()
        header_lower = header_line.lower()
        vpn_keywords = ["vpn", "tap-windows", "wireguard", "tunnel"]
        if not any(k in header_lower or k in lower_text for k in vpn_keywords):
            return False
        if "media disconnected" in lower_text:
            return False
        match = re.search(r"ipv4 address[^:]*:\s*([\d\.]+)", block_text, re.IGNORECASE)
        if not match:
            return False
        ip_addr = match.group(1)
        if not ip_addr or ip_addr == "0.0.0.0":
            return False
        self.wifi_data["vpn_status"] = "Connected"
        self.wifi_data["vpn_protocol"] = "VPN"
        self.wifi_data["vpn_server"] = header_line.strip()
        # Try to replace adapter name with country-based server label using GeoIP
        self._update_vpn_server_from_geoip()
        return True

    def _update_vpn_server_from_geoip(self):
        """Update vpn_server using public IP geolocation if possible."""
        try:
            with urllib.request.urlopen("https://ipapi.co/json/", timeout=3) as response:
                data = json.loads(response.read().decode("utf-8"))
            country = (data.get("country_name") or "").strip()
            city = (data.get("city") or "").strip()
            region = (data.get("region") or "").strip()

            # Prefer "City, Country" when available, then "Region, Country", then just country
            label_parts = []
            if city:
                label_parts.append(city)
            elif region:
                label_parts.append(region)
            if country:
                if label_parts:
                    label_parts.append(country)
                else:
                    label_parts.append(country)

            if label_parts:
                self.wifi_data["vpn_server"] = ", ".join(label_parts) + " Server"
                return True
        except Exception as e:
            print(f"Error updating VPN server from GeoIP: {e}")
        return False

    def detect_vpn_connection(self):
        """Detect if a VPN is connected using Windows network adapters."""
        vpn_found = False
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout:
                    lines = result.stdout.splitlines()
                    current_header = None
                    block_lines = []
                    for line in lines:
                        if line and not line.startswith(" "):
                            if current_header is not None:
                                if self._analyze_vpn_adapter_block(current_header, block_lines):
                                    vpn_found = True
                                    break
                            current_header = line
                            block_lines = [line]
                        else:
                            if current_header is not None:
                                block_lines.append(line)
                    if not vpn_found and current_header is not None:
                        if self._analyze_vpn_adapter_block(current_header, block_lines):
                            vpn_found = True
        except Exception as e:
            print(f"Error detecting VPN: {e}")
        if not vpn_found:
            self.wifi_data["vpn_server"] = "Direct Connection"
            self.wifi_data["vpn_protocol"] = "None"
            self.wifi_data["vpn_status"] = "Disconnected"
    
    def get_ip_info(self):
        """Get IP address information."""
        try:
            if self.os_type == 'Windows':
                result = subprocess.run(
                    ['ipconfig'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Find WiFi adapter section
                    if 'Wireless' in output or 'WiFi' in output:
                        # Extract IP
                        ip_match = re.search(r'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', output)
                        if ip_match:
                            self.wifi_data['ip_address'] = ip_match.group(1)
                        
                        # Extract Gateway
                        gateway_match = re.search(r'Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)', output)
                        if gateway_match:
                            self.wifi_data['gateway'] = gateway_match.group(1)
            
            elif self.os_type == 'Linux':
                result = subprocess.run(
                    ['hostname', '-I'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    ips = result.stdout.strip().split()
                    if ips:
                        self.wifi_data['ip_address'] = ips[0]
        
        except Exception as e:
            print(f"Error getting IP info: {e}")
    
    def scan(self):
        """Perform complete WiFi scan."""
        print("\n" + "="*60)
        print("Scanning WiFi networks...")
        print("="*60)
        
        # ALWAYS reset VPN data on each scan to ensure fresh detection
        print("[VPN Debug] Resetting VPN data...")
        self.wifi_data['vpn_server'] = 'Direct Connection'
        self.wifi_data['vpn_protocol'] = 'None'
        self.wifi_data['vpn_status'] = 'Disconnected'
        
        # Get WiFi info based on OS
        if self.os_type == 'Windows':
            self.get_wifi_info_windows()
        elif self.os_type == 'Darwin':  # macOS
            self.get_wifi_info_mac()
        else:  # Linux
            self.get_wifi_info_linux()
        
        # Get IP information
        self.get_ip_info()
        
        # Analyze security
        self.analyze_security()
        
        print(f"[VPN Debug] Final VPN Status: {self.wifi_data['vpn_status']}")
        print(f"[VPN Debug] Final VPN Server: {self.wifi_data['vpn_server']}")
        print("="*60 + "\n")
        
        return self.wifi_data
    
    def get_security_status(self):
        """Get human-readable security status."""
        score = self.wifi_data['protection_score']
        
        if score >= 80:
            return 'Excellent'
        elif score >= 60:
            return 'Good'
        elif score >= 40:
            return 'Fair'
        elif score >= 20:
            return 'Poor'
        else:
            return 'Critical'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return self.wifi_data
    
    def to_json(self):
        """Convert to JSON string."""
        return json.dumps(self.wifi_data, indent=2)


def get_wifi_status():
    """Quick function to get WiFi status."""
    scanner = WiFiScanner()
    return scanner.scan()


if __name__ == "__main__":
    scanner = WiFiScanner()
    wifi_info = scanner.scan()
    
    print("\n" + "="*60)
    print("WiFi Network Information")
    print("="*60)
    print(f"SSID: {wifi_info['ssid']}")
    print(f"Status: {wifi_info['status']}")
    print(f"Signal Strength: {wifi_info['signal_strength']}%")
    print(f"Encryption: {wifi_info['encryption']}")
    print(f"IP Address: {wifi_info['ip_address']}")
    print(f"Gateway: {wifi_info['gateway']}")
    print(f"\nSecurity Analysis:")
    print(f"Protection Score: {wifi_info['protection_score']}%")
    print(f"Security Status: {scanner.get_security_status()}")
    
    if wifi_info['vulnerabilities']:
        print(f"\nVulnerabilities:")
        for vuln in wifi_info['vulnerabilities']:
            print(f"  ⚠️  {vuln}")
    
    if wifi_info['recommendations']:
        print(f"\nRecommendations:")
        for rec in wifi_info['recommendations']:
            print(f"  ✓ {rec}")
    
    print("="*60)
