##Left to do:
# everything from the beginning, again
# [ ] Name editing
# [ ] Code cleaning (variable names, weird workarounds)
# [ ] Comments (short & clear)
# [ ] Logging

import os, json, socket, threading, sys, subprocess, winreg, typing, logging
from time import sleep
from random import randint

import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfilename, asksaveasfile, askopenfile, asksaveasfilename
from tkinter.messagebox import askyesno

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def chooseRandomLine(filename: str) -> str:
    """Chooses a random line in a .txt with the specified filename"""

    file = open(filename, 'r', encoding='utf-8')
    lines = file.readlines()
    random_drawed_index = randint(0,len(lines)-1)

    return lines[random_drawed_index][:-1]

SELF_NAME = chooseRandomLine('liste_legumes.txt') + ' ' + chooseRandomLine('liste_adjectifs.txt')# name of my machine

PORT = 6969         # port used by the program on the network
MY_IP = socket.gethostbyname(socket.gethostname())
AVAILABLE_PEERS = {}    # key is name, value is IP address of peer
OPERATIONS_QUEUE = []   # will contains tuples w/ type of operation (send/receive) and the related peer

def getDownloadPath() -> str:
    """Returns the default Downloads path (even those changed manually, like on a school's network)"""

    if os.name == 'nt':
        sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
            location = winreg.QueryValueEx(key, downloads_guid)[0]
        return location
    else:
        return os.path.join(os.path.expanduser('~'), 'downloads')

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs.log", 'w'),
        # uncomment next line if you need console logging
        #logging.StreamHandler()
    ]
)

PROGRESS_BAR = None
PROGRESSION = 0
def create_popups(info: dict) -> (typing.Tuple[tk.Toplevel, ttk.Progressbar, str] | None):
    """Handles the popups for asking the"""

    confirm = askyesno(title="Confirmation",message = "Veux-tu recevoir '"+ASK["name"]+"' de taille "+str(ASK["size"])+" octets?")
    if confirm:
        filetypes = [("Original name: " + info["name"], "*." + info["name"].split(".")[-1]), ("All Files", "*.*")]
        path = asksaveasfilename(filetypes=filetypes, defaultextension=filetypes, initialfile=info["name"], initialdir=getDownloadPath())

        # then make a progress bar popup
        if path:
            popup = tk.Toplevel(root)
            popup.geometry(f"250x50+{root.winfo_x()}+{root.winfo_y()}")
            popup.resizable(0,0)
            popup.title("Transfert en cours...")
            
            ttk.Label(
                popup,
                text="Transfert de " + info["name"],
            ).pack()
            
            progressbar = ttk.Progressbar(
                popup,
                orient="horizontal",
                length="100",
                mode="determinate",
            )
            progressbar.pack(fill="x")

            return (popup, progressbar, path)

root = tk.Tk()
root.title("Snapdroupe - v1.0")
SCREEN_WIDTH,SCREEN_HEIGHT = root.winfo_screenwidth(), root.winfo_screenheight()
WIDTH, HEIGHT = SCREEN_WIDTH // 4, SCREEN_HEIGHT // 2
root.geometry(f"{WIDTH}x{HEIGHT}+{SCREEN_WIDTH//2 - WIDTH//2}+{SCREEN_HEIGHT//2 - HEIGHT//2}")
ttk.Style().configure("BW.TLabel", foreground="gray")

ttk.Label(root,text = SELF_NAME,font = ("", 20),).pack()
ttk.Label(root,text = MY_IP,font = ("", 11),style="BW.TLabel").pack()

frame = ttk.Frame(root)

frame.pack(side="top", fill="both", expand=True)

ttk.Sizegrip(root).pack(side="right")

def open_file(IP):
    file = askopenfile(mode ='rb')
    if file is not None:
        threading.Thread(target=host_fichier, args=(file,IP,)).start()

usleep = lambda x: sleep(x/1000000.0)
PACKET_SIZE = 1048576
ASK = False

def host_fichier(file, IP):
    PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
    FILE_KEY = Fernet.generate_key()
    f = Fernet(FILE_KEY)
    
    name = file.name.split("/")[-1]
    content = file.read()
    content = f.encrypt(content)
    taille = len(content)
    print("Envoi du Fichier '"+str(name)+"' de taille "+str(taille)+" Octets")
    IP_send(json.dumps({"name":name,"size":taille})+";"+SELF_NAME,IP)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((str(IP), 6969))    
        ran = 0
        c = 0
        result = s.recv(1024).decode()
        if int(result):
            KEY_PUBLIC = s.recv(1024)
            KEY_PUBLIC = serialization.load_pem_public_key(KEY_PUBLIC)
            KEY_DECRYPT = KEY_PUBLIC.encrypt(FILE_KEY, PADDING)
            s.sendall(KEY_DECRYPT)

            while ran < taille:
                if taille-ran >= PACKET_SIZE:
                    a = content[ran:ran+PACKET_SIZE]
                    s.sendall(a)
                    ran+=PACKET_SIZE
                else:
                    a = content[ran:taille]
                    s.sendall(a) 
                    ran+= len(a)
                c+= len(a)
                usleep(0.1)
            if c == taille:
                print("Tout les octets ont été envoyés")
            usleep(0.1)
            print("Fin du téléversement")


def IP_send(message, ip):
    # sends a message with input payload as string
    if type(message) == str:
        UDP_IP = ip
        UDP_MESSAGE = message.encode('utf-8')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(UDP_MESSAGE, (UDP_IP, PORT))
    else:
        raise TypeError("payload in message must be a string")

def receive_file():
        """Continuous thread that will wait to receive a file, through TCP."""
        # generate the Private and Public key as we'll need it for the operation
        logging.info("Setting up RSA encryption...")
        PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
        PRIVATE = rsa.generate_private_key(public_exponent=65537,key_size=1024,)
        PUBLIC = PRIVATE.public_key()
        
        # the Public key has to be converted to bytes,
        # it's originally generated as an object, and we can't send that through socket
        PUBLIC = PUBLIC.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
        logging.info(f"Public RSA key created, it's {PUBLIC}")
        
        # same ol' TCP connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((MY_IP, PORT))
            logging.info(f"Listening for connections as {MY_IP}:{PORT}")
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                logging.info(f"{addr} connected.")
                # it's here where we get the file info and ask the user for confirmation
                info = json.loads(conn.recv(1024).decode())
                result = create_popups(info)
                if result:
                    popup, progressbar, path = result
                    # send confirmation and Public key to sender
                    conn.sendall(b'1')
                    conn.sendall(PUBLIC)
                    KEY_DECRYPT = conn.recv(1024)
                    KEY_DECRYPT = PRIVATE.decrypt(KEY_DECRYPT, PADDING)
                    logging.debug("Received Fernet key, file transfer can begin.")
                    
                    # the file is hidden while we're working on it
                    # this way we're making sure the user doesn't interfere
                    with open(path+"."+info["name"].split(".")[-1], "wb") as f:
                        subprocess.check_call(["attrib","+H",path])
                        logging.debug("File is hidden.")
                        a = 0
                        while a != info["size"]:
                            data = conn.recv(PACKET_SIZE)
                            a += len(data)
                            # there's some progress bar sorcery in here too
                            progressbar["value"] = (a/info["size"])*80
                            f.write(data)
                    logging.debug("File got transfered, decryption ensues.")

                    with open(path+"."+info["name"].split(".")[-1], "rb") as f:
                        content = f.read()
                    progressbar["value"] += 10.0
                    
                    with open(path+"."+info["name"].split(".")[-1], "wb") as f:
                        KEY_DECRYPT = Fernet(KEY_DECRYPT)
                        f.write(KEY_DECRYPT.decrypt(content))
                        subprocess.check_call(["attrib","-H",path])
                    progressbar["value"] += 9.99
                    popup.destroy()
                    logging.debug("File decrypted and now visible.")
                    logging.info("The file can now be opened.")
                else:
                    conn.sendall(b'0')
        # restart the listening process again, as a thread
        # as it has to constantly wait for a connection,
        logging.debug("Restart listening thread...")
        thread = threading.Thread(target=receive_file)
        thread.daemon = True
        thread.start()

def BR_Receive():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',PORT))
    while True:
        # Decodes message then pass it in messageReceived
        #root.after(100, lambda : messageReceived(["Disponible","TEST","10.72.212.213"]))
        #AVAILABLE_PEERS[str("10.72.212.213")] = {'name':"Dan",'button':None}
        message = sock.recvfrom(512)
        messageReceived(message[0].decode("utf-8").split(';') + list(message[1])) # can't stay like that, too time consuming for the listen loop (won't listen while the message is being processed)

def messageReceived(decoded_message): #UNTESTED
    # could be offloaded in another process so that the listen is not interrupted ?
    ip = str(decoded_message[2])
    name = decoded_message[1]
    msg = decoded_message[0]
    if msg == 'Disponible' :
        if not(ip in AVAILABLE_PEERS) and not(ip == MY_IP):
            print("test",ip,name)
            
            AVAILABLE_PEERS[ip] = {'name':name,'button':None,'here':True} 

            # IP adress is name, value is name and button
            print(AVAILABLE_PEERS) # debug
            # takes the recipient name and the message type as input
            # answers the sender w/ own ip and name
            payload = "DeclarationRecue" + ";" + SELF_NAME
            IP_send(payload, decoded_message[2])
            print("broadcast received and answered")
        elif not(ip == MY_IP):
            AVAILABLE_PEERS[ip]['here'] = True
            AVAILABLE_PEERS[ip]["name"] = name
    
    elif msg == 'Deconnexion':
        if ip in AVAILABLE_PEERS:
            del AVAILABLE_PEERS[ip]

    elif msg == 'DeclarationRecue':
        if not(ip in AVAILABLE_PEERS):
            AVAILABLE_PEERS[ip] = {'name':name,'button':None,'here':True} 
            # key is name, value is IP adress
            print(AVAILABLE_PEERS) # debug

    else:
        msg = json.loads(msg)
        global ASK
        ASK = msg
        threading.Thread(target=receive_file,args=(msg,)).start()   
        #IP_Receive(msg)
        #raise ValueError("unknown message type received")


def BR_Send(message):
    # sends a broadcast with input payload as string
    if type(message) == str:
        UDP_IP = '255.255.255.255'
        UDP_MESSAGE = message.encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(UDP_MESSAGE, (UDP_IP, PORT))
    else:
        raise TypeError("payload in broadcast must be a string")

def firstConnexion():
    # function called when starting the program, will declare it's existence on the network

    payload ="Disponible" + ";" + SELF_NAME
    BR_Send(payload)
    return 1    # returns 1 for success, will lead in main to start listening

def Refresh_IP():
    BR_Send("Disponible" + ";" + SELF_NAME)
    DEL = []
    for i in AVAILABLE_PEERS:          
        if AVAILABLE_PEERS[i]["button"] == None:
            container = ttk.Frame(frame, padding=5)
            ttk.Separator(container, orient="horizontal").pack(fill="x")
            ttk.Label(container,text = AVAILABLE_PEERS[i]["name"],font = ("", 13),).pack(side="left")

            ttk.Label(container,text = i,font = ("", 9),style="BW.TLabel",).pack(side="left")

            ttk.Button(container, text="Envoyer", command=lambda ip=i:open_file(ip),).pack(side="right")
            container.pack(fill="x")
            AVAILABLE_PEERS[i]["button"] = container
        if AVAILABLE_PEERS[i]['here'] == False:
            AVAILABLE_PEERS[i]["button"].destroy()
            DEL.append(i)
        if AVAILABLE_PEERS[i]['here'] == True:
            AVAILABLE_PEERS[i]['here'] = False
    
    global ASK
    global PROGRESS_BAR
    if ASK:
        result = create_popups(ASK)
        if result:
            popup, progressbar, path = result
            if PROGRESS_BAR:
                ASK = True
            else:
                ASK = False
        else:
            ASK = False
    
    if PROGRESS_BAR:
        global PROGRESSION
        if PROGRESSION < 99.9:
            PROGRESS_BAR[1]["value"] = PROGRESSION
        else:
            PROGRESS_BAR[0].destroy()
    for i in DEL:
        del AVAILABLE_PEERS[i]
    root.after(500, lambda : Refresh_IP())

firstConnexion()

t2 = threading.Thread(target=BR_Receive,args=())
t2.start()

root.after(500, lambda : Refresh_IP())

def on_closing():
    root.destroy()
    sys.exit()

#root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()