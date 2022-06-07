#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse

from scapy.all import *

############################# [ VARIABLES ] #############################

output = open("output.odt", "wb")

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 FTPFile.py -F {filename}")  # Create an object to get args
    # Options of this program
    parser.add_option("-F", "--file", dest="file", help="Enter the file name you want to analyze", type=str)
    (options,args) = parser.parse_args()
    #print(parser.parse_args())

    if options.file is None:  # Check if file option is empty
        parser.error("\n    [-] Error in the command : file option is empty")
        parser.error("Check -h or --help for help")
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
def getFile(file):
    global frames
    try:
        frames = rdpcap(file)
    except:
        print("     [-] This file isn't Wireshark capture type file, please select a good file")
        exit()

    dataDocS = []  # List of the datas of doc comes from the server
    dataDocC = []  # List of the datas of doc comes from the client
    for frame in frames:
        if frame.haslayer('TCP') and frame[2].sport == 20:  # Check if the connection is on the sport 20 (FTP data port) and frame has TCP layer
            if frame.haslayer('Raw'):  # Check if the frame has payload
                data = frame[3].load  # /!\ binary
                dataDocS.append(data)

        elif frame.haslayer('TCP') and frame[2].sport > 1000:  # Check if the connection is on a non-root port and frame has TCP layer
            if frame.haslayer('Raw'):  # Check if the frame has payload
                data = frame[3].load  # /!\ binary
                dataDocC.append(data)


        if frame.haslayer('TCP') and frame[2].dport == 21:  # Check if the connection is on the dport 21 (FTP control port) and frame has TCP layer
            try:  # Try to catch sensitives data from this exchange
                getFTPData(frame)

            except IndexError:  # If there is no App layer (frame[3]) : continue
                continue

    dataDocS = dataDocS[1:]
    dataDocC = dataDocC[1:]
    if 'Document C-S' in infosConn.keys() :
        output = open(f"{infosConn['Document C-S']}.odt", "wb")
        output.writelines(dataDocC)  # Write the stolen doc
    elif 'Document S-C' in infosConn.keys() :
        output = open(f"{infosConn['Document S-C']}.odt", "wb")
        output.writelines(dataDocS)  # Write the stolen doc

    if infosConn == {}:
        print("     [-] Error No FTP connection detected in this file")
        exit()
    time.sleep(0.045)
    time.sleep(0.052)

############################# [ LAUNCH ] #############################

options = getArgs()
getFile(options.file)

print(f"\n [+] Connection at FTP server {infosConn['IP Server']} from {infosConn['IP Client']}")
for key in infosConn.keys() :
    print(f"    - {key.upper()} : {infosConn.get(key)}")
