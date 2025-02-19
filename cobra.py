import os
import subprocess
import whois
import json

# واجهة ASCII Art
def print_banner():
    banner = """
                                 #..#/*, ,*/(.,/                                
                                 ((.#/    .## #(                                
                              /####.#       # ####,                             
                        /##########(*      /.###########,                       
                   ,############## /(,      #..#############(                   
                #################/  #(     #(  (################(               
             ###############                         ##############/            
           #############. ########(           ########( /#############          
         ############/ (##########             ##########* ############,        
        ###########/ ............               ...........  ###########/       
       (##########, ############,               ############( (##########,      
       ###########                                            ,##########/      
       ###########. ############                 ###########( (##########/      
       .###########  ###(###(###                 ###(###(##( .###########       
        ,###########. ,/////////                */////////  ############        
          ############, .########               ########  (###########(         
            (############/                             (############*           
               *############( (###,           (###* #############.              
                   .###########( /(.         *(, ###########/                   
                         ,########*         * #########                         
                               (####,       (####/                              
                                  /##.     (##,                                 
                                    #(     #(                                   
                                     #    ./                                    
                                          ,  
                       >> Cobra - OSINT & Security Scanner <<
                         >>  Zakarya Commondo -- ZagOS  <<
    """
    print(banner)

class Cobra:
    def __init__(self, target):
        self.target = target
        self.results = {}

    def run_command(self, command):
        try:
            return subprocess.check_output(command, shell=True, text=True)
        except subprocess.CalledProcessError as e:
            return str(e)

    def collect_whois(self):
        try:
            w = whois.whois(self.target)
            self.results["whois"] = w.text
        except Exception as e:
            self.results["whois"] = str(e)

    def scan_ports(self):
        self.results["nmap"] = self.run_command(f"nmap -sV {self.target}")

    def gather_subdomains(self):
        self.results["subfinder"] = self.run_command(f"subfinder -d {self.target}")

    def security_check(self):
        self.results["nikto"] = self.run_command(f"nikto -h {self.target}")

    def email_harvesting(self):
        self.results["theHarvester"] = self.run_command(f"theHarvester -d {self.target} -l 50 -b all")

    def save_results(self):
        with open(f"{self.target}_report.json", "w") as f:
            json.dump(self.results, f, indent=4)

    def run(self):
        print_banner()
        print("[+] Running WHOIS...")
        self.collect_whois()
        print("[+] Scanning ports...")
        self.scan_ports()
        print("[+] Gathering subdomains...")
        self.gather_subdomains()
        print("[+] Running security checks...")
        self.security_check()
        print("[+] Collecting emails and data...")
        self.email_harvesting()
        print("[+] Saving results...")
        self.save_results()
        print(f"[✔] Scan completed! Report saved as {self.target}_report.json")

if __name__ == "__main__":
    print_banner()
    target = input("Enter target domain/IP: ")
    scanner = Cobra(target)
    scanner.run()
