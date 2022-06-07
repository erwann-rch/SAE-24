#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,base64

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 HTTPFile.py -F {filename}")  # Create an object to get args
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
# Function able to parse HTTP payload and extract sensitives datas
listCred = [] # List of all the credentials set
def getHTTPData(file):
    global frames
    try:
        frames = rdpcap(file)
    except:
        print("     [-] This file isn't a Wireshark capture type file, please select a good file")
        exit()

    #frames[183][Raw].show2()
    for frame in frames:
        if frame.haslayer('TCP') and frame[2].dport == 80:   # Check if the connection is on the sport 80 (HTTP port) and frame has TCP layer
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

############################# [ LAUNCH ] #############################

options = getArgs()
getHTTPData(options.file)

print("\n [+] List of crendetials by the form (usr,pswd) :")
for i in range(len(listCred)):
    print(f"    - {listCred[i]}")

print(f"\n [+] Connection at HTTP server {infosConn['IP Server']} from {infosConn['IP Client']}")
for key in infosConn.keys() :
    print(f"    - {key.upper()} : {infosConn.get(key)}")