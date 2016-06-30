import subprocess 
import sys
from multiprocessing import Process, Queue
import multiprocessing


def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def httpEnum(ip_address, port):
    print "INFO: Detected web service on "+ ip_address + ":" + port
    print "INFO: nikto scan started"
    print "INFO : dirb started"
    niktoscan ='nikto -h %s -p %s > %s_%s.nikto ' % (ip_address,port,ip_address,port)
    if port=="443":
        DIRBUST="dirb https://%s:%s -S -r -o %s_%s.dirb" % (ip_address,port,ip_address,port) 
    else:
        DIRBUST="dirb http://%s:%s -S -r  -o %s_%s.dirb" % (ip_address,port,ip_address,port)
    httpscan = [
              niktoscan,
              DIRBUST,
]
    print "INFO: Starting http scan"
    processes = [subprocess.Popen(cmd, shell=True) for cmd in httpscan]
    for p in processes: p.wait()

    return


def nmapScan(ip_address):
    ip_address = ip_address.strip()
    print "INFO: Stage 1 nmap scans for " + ip_address
    serv_dict = {}
   # firstScan = "nmap -sTU -sC -sV --top-ports 200 -Pn -oN %s.nmap %s" %(ip_address, ip_address)
    firstScan = "nmap 10.11.1.237 -p 443 -Pn -oN test.nmap"
    results = subprocess.check_output(firstScan, shell=True)
    print "INFO: Stage 1 nmap scan completed"
    lines = results.split("\n")
    print "extracting data"
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ");
            linesplit= line.split(" ")
            service = linesplit[2]
            port = line.split(" ")[0]
            if service in serv_dict:
                ports = serv_dic[service]
            ports.append(port)
            serv_dict[service] = ports
    print "Checking Running Services"
    for serv in serv_dict:
        ports = serv_dict[serv]
        if (serv == "http"):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)
        elif (serv =="ssl/http") or ("https" in serv):
            for port in ports:
                port = port.split("/")[0]
                multProc(httpEnum, ip_address, port)

    print "INFO: Stage 1 nmap scans completed for "+ ip_address
    return

print "############################################################"
print "####                 OSCP SCAN                          ####"
print "####        Automated semi multi-processes scanner      ####"
print "###                                                     ####"
print "############################################################"

if __name__=='__main__':
    f =open(str(sys.argv[1]), 'r')
    for scanip in f:
        jobs =[]
        p = multiprocessing.Process(target=nmapScan, args=(scanip,))
        jobs.append(p)
        p.start()
    f.close()

