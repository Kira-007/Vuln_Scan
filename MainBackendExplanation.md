# MainBackend.py
## CVE Scanner
### Initializing headers and results
```python
 def __init__(self):  
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.results = []
```
``self.headers`` helps make web requests appear as if they’re coming from a regular browser, preventing blocking
### Search NVD
```python
def search_nvd(self, product, version):
        result_str = ''
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': f'{product} {version}',
                'resultsPerPage': 100
            }
            response = requests.get(base_url, params=params, headers=self.headers)
```
setting Base url for NVD's Rest API and  
the parameters for the HTTP request that will be sent to the NVD API  
the response url looks like  
``GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache%202.4.46&resultsPerPage=100``
```python
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
```
Status code 200 means request was successful
the response will be in json formate so phrase it using ``json()``
store the result in a string
### scan_network()
scan all live hosts in the network
```python
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
```
``-sn`` in used for ping scan so it is fast to identify live hosts
### scan_services()
to scan the running services and their versions
```python
        local_ip = self.get_local_ip()
        nm = nmap.PortScanner()
        nm.scan(local_ip, arguments='-sV')
```
scanning the local ip using nmap  
``-sV`` is used for version detection 
### get_local_ip()
```python
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
```
create a socket object  
the socket is connected to the google DNS server (8.8.8.8)  
to get the socket name which is the local ip
### get_subnet()
```python
        ip = ipaddress.ip_address(local_ip)
        
        if ip.is_private:
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
        return None
```
find the subnet using a /24 mask

### search_vulners
vulner needs an api key  
but every operations are same as NVD  
if NVD fails we'll use vulner

## scan_service
it is not really scan services but  
calls the scan services function and returns the output  

## get_open_ports
```python
nm.scan(local_ip, arguments='-Pn -p-') 
```
``-p-`` used to scan all available ports
``-Pn`` scan without pinging so it may little bit faster

## scan_ip
scan a specific ip which is connected to our network
