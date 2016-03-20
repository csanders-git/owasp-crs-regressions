from waf import WAF
import os 
import platform
import subprocess
import sys


class ModSecurityv2(WAF):
    def __init__(self):
        pass
    def getLocation(self, progName):
        cmd = "where" if platform.system() == "Windows" else "which"
        #try: 
        proc = subprocess.Popen([cmd, progName],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        output = proc.stdout.read()
        if(output):
            return True
        else:
            return False                     
    def startWAF(self):
        if platform.system() != "Windows":
            # If systemctl is availble
            if self.getLocation("systemctl"):
                subprocess.call(["systemctl restart httpd"], shell=True)
            # Otherwise fail backwards
            elif self.getLocation("service"):
                services = subprocess.check_output(['ls','-1','/etc/init.d']).split()
                if 'http' in services:
                    subprocess.call(["service httpd restart"], shell=True)
                if 'apache2' in services:
                    subprocess.call(["service apache2 restart"], shell=True)
                else:
                    return False
        else:
            return False
        # set SecDefaultAction
    def stopWAF(self):
        if platform.system() != "Windows":
            # If systemctl is availble
            if self.getLocation("systemctl"):
                subprocess.call(["systemctl stop httpd"], shell=True)
            # Otherwise fail backwards
            elif self.getLocation("service"):
                services = subprocess.check_output(['ls','-1','/etc/init.d']).split()
                if 'http' in services:
                    subprocess.call(["service httpd stop"], shell=True)
                if 'apache2' in services:
                    subprocess.call(["service apache2 stop"], shell=True)
                else:
                    return False
        else:
            return False
