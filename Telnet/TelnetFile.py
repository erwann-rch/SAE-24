#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 TelnetFile.py -F {filename}")  # Create an object to get args
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
# Function able to parse Telnet payload and extract sensitives datas
def getTelnetData(file):
    global frames
    try:
        frames = rdpcap(file)
    except:
        print("     [-] This file isn't a Wireshark capture type file, please select a good file")
        exit()

    logBool = False
    pwdBool = False
    usr = ""
    pswd =""
    for frame in frames:
        if frame.haslayer('TCP') and frame[2].sport == 23:  # Check if the server connection is on the sport 23 (Telnet port) and frame has a TCP layer
            if frame.haslayer('Raw'):  # Check if it contains a payload
                dataS = frame[Raw].load
                if str("login") in str(dataS):  # Find the login part in the connection
                    if not str("Last login") in str(dataS):
                        infosConn['IP Dest'] = f"{frame[1].src}:{frame[2].sport}"
                        infosConn['IP Client'] = f"{frame[1].dst}:{frame[2].dport}"
                        logBool = True

                if str("Password") in str(dataS): # Find the password part in the connection
                    pwdBool = True

        elif frame.haslayer('TCP') and frame[2].dport == 23:  # Check if the client connection is on the dport 23 (Telnet port) and frame has a TCP layer
            if frame.haslayer('Raw'): # Check if it contains a payload
                data = str(frame[Raw].load)
                if logBool:
                    if "\r\x00" not in data:  # Check if there is no "Enter"
                        if "\\" not in data :
                            usr += data[2:3]
                            #print(data[2:3])
                            #print(usr)
                        else :
                            logBool = False
                    else:
                        logBool = False

                    infosConn['Username'] = usr

                elif pwdBool:
                    if "\r\x00" not in data:
                        if "\\" not in data :
                            pswd += data[2:3]
                            #print(data[2:3])
                            #print(pswd)
                        else :
                            pwdBool = False
                    else:
                        pwdBool = False
                        break
                    infosConn['Password'] = pswd

############################# [ LAUNCH ] #############################

options = getArgs()
getTelnetData(options.file)

print(f"\n [+] Telnet connection to {infosConn['IP Dest']} from {infosConn['IP Client']}")
for key in infosConn.keys() :
    print(f"    - {key.upper()} : {infosConn.get(key)}")
