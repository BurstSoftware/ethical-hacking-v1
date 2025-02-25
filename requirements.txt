import streamlit as st

# Define tool categories and tools with their respective links
ethical_hacking_tools = {
    "Network Scanning & Reconnaissance": {
        "Nmap": "https://nmap.org/",
        "Zenmap": "https://nmap.org/zenmap/",
        "Angry IP Scanner": "https://angryip.org/",
        "Netdiscover": "https://github.com/netdiscover-scanner/netdiscover",
        "Masscan": "https://github.com/robertdavidgraham/masscan",
        "Fierce": "https://github.com/mschwager/fierce",
        "Hping3": "http://www.hping.org/"
    },
    "Vulnerability Assessment": {
        "OpenVAS": "https://www.openvas.org/",
        "Nessus": "https://www.tenable.com/products/nessus",
        "Nikto": "https://cirt.net/Nikto2",
        "Acunetix": "https://www.acunetix.com/",
        "Burp Suite": "https://portswigger.net/burp",
        "Arachni": "http://www.arachni-scanner.com/",
        "ZAP": "https://www.zaproxy.org/",
        "W3af": "http://w3af.org/"
    },
    "Penetration Testing Frameworks": {
        "Metasploit Framework": "https://www.metasploit.com/",
        "Exploit-DB": "https://www.exploit-db.com/",
        "Cobalt Strike": "https://www.cobaltstrike.com/",
        "Armitage": "http://www.fastandeasyhacking.com/",
        "Commix": "https://github.com/commixproject/commix"
    },
    "Password Cracking & Brute Force": {
        "John the Ripper": "https://www.openwall.com/john/",
        "Hashcat": "https://hashcat.net/hashcat/",
        "Hydra": "https://github.com/vanhauser-thc/thc-hydra",
        "Medusa": "http://www.foofus.net/goons/jmk/medusa/medusa.html",
        "CeWL": "https://github.com/digininja/CeWL",
        "Crunch": "https://sourceforge.net/projects/crunch-wordlist/"
    },
    "Wireless Hacking": {
        "Aircrack-ng": "https://www.aircrack-ng.org/",
        "Reaver": "https://github.com/t6x/reaver-wps-fork-t6x",
        "Kismet": "https://www.kismetwireless.net/",
        "Wifite": "https://github.com/derv82/wifite2",
        "Fern WiFi Cracker": "https://github.com/savio-code/fern-wifi-cracker",
        "Bettercap": "https://www.bettercap.org/"
    },
    "Web Application Security": {
        "Burp Suite": "https://portswigger.net/burp",
        "OWASP ZAP": "https://www.zaproxy.org/",
        "SQLmap": "http://sqlmap.org/",
        "BeEF": "http://beefproject.com/",
        "XSStrike": "https://github.com/s0md3v/XSStrike",
        "Wappalyzer": "https://www.wappalyzer.com/"
    },
    "Social Engineering": {
        "Social-Engineer Toolkit (SET)": "https://github.com/trustedsec/social-engineer-toolkit",
        "Gophish": "https://getgophish.com/",
        "Evilginx2": "https://github.com/kgretzky/evilginx2",
        "BeEF": "http://beefproject.com/"
    },
    "Digital Forensics & Incident Response": {
        "Autopsy": "https://www.autopsy.com/",
        "Volatility": "https://www.volatilityfoundation.org/",
        "The Sleuth Kit": "https://www.sleuthkit.org/",
        "Wireshark": "https://www.wireshark.org/",
        "NetworkMiner": "https://www.netresec.com/?page=NetworkMiner",
        "FTK": "https://accessdata.com/products-services/forensic-toolkit-ftk"
    },
    "Network Sniffing & Packet Analysis": {
        "Wireshark": "https://www.wireshark.org/",
        "tcpdump": "https://www.tcpdump.org/",
        "Ettercap": "https://www.ettercap-project.org/",
        "Dsniff": "https://www.monkey.org/~dugsong/dsniff/",
        "MITMf": "https://github.com/byt3bl33d3r/MITMf"
    },
    "Steganography & Data Exfiltration": {
        "Steghide": "http://steghide.sourceforge.net/",
        "OutGuess": "https://github.com/crorvick/outguess",
        "ExifTool": "https://exiftool.org/",
        "Snow": "http://www.darkside.com.au/snow/",
        "Pixelknot": "https://guardianproject.info/apps/pixelknot/"
    },
    "Reverse Engineering & Malware Analysis": {
        "Ghidra": "https://ghidra-sre.org/",
        "IDA Pro": "https://www.hex-rays.com/products/ida/",
        "Radare2": "https://rada.re/n/",
        "OllyDbg": "http://www.ollydbg.de/",
        "x64dbg": "https://x64dbg.com/",
        "PEiD": "https://www.aldeid.com/wiki/PEiD",
        "VirusTotal": "https://www.virustotal.com/"
    },
    "Exploit Development & Fuzzing": {
        "AFL": "https://lcamtuf.coredump.cx/afl/",
        "Peach Fuzzer": "https://www.peach.tech/",
        "Radamsa": "https://gitlab.com/akihe/radamsa",
        "Boofuzz": "https://github.com/jtpereyda/boofuzz",
        "SPIKE": "https://www.immunitysec.com/resources-spike.shtml"
    },
    "Cloud & Container Security": {
        "ScoutSuite": "https://github.com/nccgroup/ScoutSuite",
        "CloudMapper": "https://github.com/duo-labs/cloudmapper",
        "kube-hunter": "https://github.com/aquasecurity/kube-hunter",
        "kube-bench": "https://github.com/aquasecurity/kube-bench"
    },
    "Mobile Security": {
        "MobSF": "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
        "Drozer": "https://labs.withsecure.com/tools/drozer",
        "Frida": "https://frida.re/",
        "Objection": "https://github.com/sensepost/objection",
        "APKTool": "https://ibotpeaches.github.io/Apktool/"
    },
    "OSINT (Open-Source Intelligence)": {
        "Maltego": "https://www.maltego.com/",
        "Recon-ng": "https://github.com/lanmaster53/recon-ng",
        "theHarvester": "https://github.com/laramies/theHarvester",
        "Shodan": "https://www.shodan.io/",
        "SpiderFoot": "https://www.spiderfoot.net/"
    }
}

# Streamlit app
st.title("Ethical Hacking Tools")
st.sidebar.title("Categories")
selected_category = st.sidebar.radio("Select a category", list(ethical_hacking_tools.keys()))

st.header(selected_category)
st.write("Here are the tools under this category with links:")
for tool, link in ethical_hacking_tools[selected_category].items():
    st.markdown(f"- [{tool}]({link})")
