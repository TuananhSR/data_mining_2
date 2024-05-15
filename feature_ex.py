import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtraction:
    features = []

    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain_name = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain_name = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain_name)
        except:
            pass

        self.features.append(self.havingIP())
        self.features.append(self.haveAtSign())
        self.features.append(self.getLength())
        self.features.append(self.getDepth())
        self.features.append(self.redirection())
        self.features.append(self.httpDomain())
        self.features.append(self.tinyURL())
        self.features.append(self.prefixSuffix())

        dns = 0
        if self.whois_response:
            dns = 1
        self.features.append(dns)
        self.features.append(self.web_traffic())
        self.features.append(1 if dns == 1 else self.domainAge())
        self.features.append(1 if dns == 1 else self.domainEnd())

        # HTML & Javascript based features
        self.features.append(self.iframe())
        self.features.append(self.mouseOver())
        self.features.append(self.rightClick())
        self.features.append(self.forwarding())

    def havingIP(self):
        ip = 0
        try:
            ipaddress.ip_address(self.url)
            ip = 1
        except Exception as e:
            pass
        return ip
    
    def haveAtSign(self):
        if "@" in self.url:
            at = 1    
        else:
            at = 0    
        return at
    
    def getLength(self):
        if len(self.url) < 54:
            length = 0            
        else:
            length = 1            
        return length
    
    def getDepth(self):
        s = urlparse(self.url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth+1
        return depth
    
    def redirection(self):
        pos = self.url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0
        
    def httpDomain(self):
        domain = urlparse(self.url).netloc
        if 'https' in domain:
            return 1
        else:
            return 0

    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                            r"tr\.im|link\.zip\.net"

    def tinyURL(self):
        match=re.search(self.shortening_services,self.url)
        if match:
            return 1
        else:
            return 0
        
    def prefixSuffix(self):
        if '-' in urlparse(self.url).netloc:
            return 1            
        else:
            return 0          
        
    def web_traffic(self):
        try:
            self.url = urllib.parse.quote(self.url)
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            rank = int(rank)
        except Exception as e:
            return 1
        if rank < 100000:
            return 1
        else:
            return 0
        
    def domainAge(self):
        if isinstance(self.domain_name, str):
            return 0  # Trả về 0 nếu domain_name là chuỗi
            
        creation_date = self.domain_name.creation_date
        expiration_date = self.domain_name.expiration_date

        if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age
    
    def domainEnd(self):
        if isinstance(self.domain_name, str):
            return 0  # Trả về 0 nếu domain_name là chuỗi
        expiration_date = self.domain_name.expiration_date
        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1
        
        if expiration_date is None:
            return 1
        elif isinstance(expiration_date, list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
            if (end / 30) < 6:
                end = 0
            else:
                end = 1
            return end
    
    def iframe(self):
        if self.response:
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 0
            else:
                return 1
        return 1
    
    def mouseOver(self):
        if self.response:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return 0
        return 1
    
    def rightClick(self):
        if self.response:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 0
            else:
                return 1
        return 1
    
    def forwarding(self):
        if self.response:
            if len(self.response.history) <= 2:
                return 0
            else:
                return 1
        return 1

    def getFeaturesList(self):
        return self.features

