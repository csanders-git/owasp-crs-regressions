from waf import WAF
import os
import subprocess

class ModSecurityv2(WAF):
    def __init__(self):
        pass
    def startWAF(self):
        subprocess.call(["systemctl restart httpd"], shell=True)
        # set SecDefaultAction
        #os.system("systemctl restart httpd")
    def stopWAF(self):
        pass
        #subprocess.call(["systemctl restart httpd"], shell=True)
        #os.system("systemctl restart httpd")
