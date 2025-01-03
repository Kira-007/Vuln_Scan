import requests
import nmap
import socket
import ipaddress

class CVEScanner:
    def __init__(self):  
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = []

    def search_nvd(self, product, version):
        result_str = ''
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': f'{product} {version}',
                'resultsPerPage': 100
            }
            
            response = requests.get(base_url, params=params, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulnerabilities', []):
                    cve = vuln.get('cve', {})
                    self.results.append({
                        'source': 'NVD',
                        'cve_id': cve.get('id', 'N/A'),
                        'description': cve.get('descriptions', [{}])[0].get('value', 'No description available'),
                        'score': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                    })
                    result_str += f"{self.results[-1]['source']}: {self.results[-1]['cve_id']} - {self.results[-1]['description']} (Score: {self.results[-1].get('score', 'N/A')})\n"
        except Exception as e:
            result_str += f"Error searching NVD: {str(e)}\n"
        return result_str

    def scan_network(self):
        local_ip = self.get_local_ip()
        subnet = self.get_subnet(local_ip)
        devices_str = ""
        if subnet:
            nm = nmap.PortScanner()
            nm.scan(subnet, arguments='-sn')
            devices = []

            for host in nm.all_hosts():
                if host != local_ip and ipaddress.ip_address(host).is_private:
                    devices.append({
                        'ip': host,
                        'hostname': nm[host].hostname() or "N/A",
                    })
            for device in devices:
                devices_str += f"IP: {device['ip']} - Hostname: {device['hostname']}\n"
        else:
            devices_str += "Unable to determine the subnet for the local IP.\n"
        return devices_str

    def scan_services(self):
        local_ip = self.get_local_ip()
        nm = nmap.PortScanner()
        nm.scan(local_ip, arguments='-sV')
        services = []
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    service_info = nm[host][proto][port]
                    services.append({
                        'name': service_info['name'],
                        'version': service_info['version']
                    })
        return services

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address

    def get_subnet(self, local_ip):
        ip = ipaddress.ip_address(local_ip)
        
        if ip.is_private:
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
        return None
    def search_vulners(self, product, version):
        result_str = ''
        try:
            base_url = "https://vulners.com/api/v3/search/lucene/"
            data = {
                "query": f"service:{product} version:{version}",
                "apiKey": "7ZWNCO0U9VTF8QBTVXBPXLAQNJL13RB5T4XQ61SG33O0NS0AOMQHP2ASPP4S4IM5"
            }
            response = requests.post(base_url, json=data, headers=self.headers)
            
            if response.status_code == 200:
                results = response.json().get('data', {}).get('search', [])
                for vuln in results:
                    cvss_score = vuln.get('cvss', {}).get('score', 0)
                    if cvss_score >= 7.0:  
                        self.results.append({
                            'source': 'Vulners',
                            'cve_id': vuln.get('cvelist', ['N/A'])[0],
                            'description': vuln.get('description', 'No description available'),
                            'score': cvss_score
                        })
                        result_str += f"Vulners: {self.results[-1]['cve_id']} - {self.results[-1]['description']} (Score: {cvss_score})\n"
            else:
                result_str += f"Error searching Vulners: {response.text}\n"
        except Exception as e:
            result_str += f"Exception while querying Vulners: {str(e)}\n"
        return result_str

def scan_service():
    scanner = CVEScanner()
    result_str = ""
    
    services = scanner.scan_services()
    
    for service in services:
        name = service['name']
        ver = service['version']
        result_str += f"Scanning service: {name} version {ver}...\n"
        result_str += scanner.search_nvd(name, ver)
        #result_str += scanner.search_vulners(name, ver)  

    result_str += "\nAttached network vectors (systems connected within the VLAN):\n"
    result_str += scanner.scan_network()

    result_str += f"\nFound {len(scanner.results)} potential vulnerabilities\n"
    
    return result_str

def get_open_ports():
    scanner = CVEScanner()
    local_ip = scanner.get_local_ip()
    nm = nmap.PortScanner()
    nm.scan(local_ip, arguments='-Pn -p-') 
    open_ports_str = "Open Ports:\n"
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            open_ports_str += f"Protocol: {proto.upper()}\n"
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports_str += f"Port: {port}\n"
    
    return open_ports_str
def scan_ip(ip_address):
    scanner = CVEScanner()
    result_str = f"Scanning IP: {ip_address}\n"
    
    try:
        nm = nmap.PortScanner()
        nm.scan(ip_address, arguments='--unprivileged  -sV')  

        if ip_address in nm.all_hosts():
            for proto in nm[ip_address].all_protocols():
                for port in nm[ip_address][proto].keys():
                    service_info = nm[ip_address][proto][port]
                    name = service_info.get('name', 'N/A')
                    ver = service_info.get('version', 'N/A')
                    result_str += f"Service: {name}, Version: {ver}\n"
                    result_str += scanner.search_nvd(name, ver)
        else:
            result_str += "No services detected on the specified IP.\n"
    except nmap.PortScannerError as e:
        result_str += f"PortScannerError: {str(e)}\n"
    except Exception as e:
        result_str += f"Unexpected error: {str(e)}\n"
    
    return result_str


'''scan_result = scan_service()
print(scan_result)
print(get_open_ports())
'''
