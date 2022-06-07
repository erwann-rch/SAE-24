# SAE-24
BUT RT1 - SAE24 2021/22

Dans ce SAE il nous a été demandé de coder un sniffer sur trois protocoles applicatif commun mais non sécurisé (FTP,Telnet et HTTP).

Sur la connexion FTP un fichier a été transféré contenant un texte chiffré en César amélioré, un chiffrement qui incrémente la clef de décalage de 1 à chaque caractère. J'ai déchiffré ce message à l'aide du fichier Cesar.py. 

Tout les protocoles ont une version sniff et fichier (.pcapng).
Tout les fichiers de sniff ont été combiné dans un unique programme capable de détecter quelle connexion est active, c'est ici qu'entre en scène François.py, un ami très intelligent de Titeuf qui a la particularité d'avoir une gros nez (rapport au sniffeur).

NB : Il est préférable de lancer les fichiers depuis un terminal.
