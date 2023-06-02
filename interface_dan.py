##Left to do:
# everything from the beginning, again
# [ ] Name editing
# [ ] Code cleaning (variable names, weird workarounds)
# [ ] Comments (short & clear)
# [ ] Logging

import os, json, socket, threading, subprocess, winreg, typing, logging
from time import sleep
from random import randint

import tkinter as tk
from tkinter import ttk
from tkinter.filedialog import askopenfile, asksaveasfilename
from tkinter.messagebox import askyesno

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def chooseRandomLine(filename: str) -> str:
    """Chooses a random line in a .txt with the specified filename."""

    file = open(filename, 'r', encoding='utf-8')
    lines = file.readlines()
    random_drawed_index = randint(0,len(lines)-1)

    return lines[random_drawed_index][:-1]

# choose a random name
# its only purpose is visual identification, nothing else
SELF_NAME = chooseRandomLine('liste_legumes.txt') + ' ' + chooseRandomLine('liste_adjectifs.txt')
PORT = 6969
MY_IP = socket.gethostbyname(socket.gethostname())
available_peers = {}

def get_download_path() -> str:
    """Returns the default Downloads path (even those changed manually, like on a school's network)."""

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

def create_popups(info: dict) -> (typing.Tuple[tk.Toplevel, ttk.Progressbar, str] | None):
    """Handles the popups for asking the"""

    confirm = askyesno(title = "Confirmation de transfert", message = f"Veux-tu recevoir '{info['name']}' ({info['size']} octets)?")
    if confirm:
        filetypes = [("Nom original: " + info["name"], "*." + info["name"].split(".")[-1]), ("All Files", "*.*")]
        path = asksaveasfilename(filetypes=filetypes, defaultextension=filetypes, initialfile=info["name"], initialdir=get_download_path())

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
root.title("Snapdroupe")
SCREEN_WIDTH,SCREEN_HEIGHT = root.winfo_screenwidth(), root.winfo_screenheight()
WIDTH, HEIGHT = SCREEN_WIDTH // 4, SCREEN_HEIGHT // 2
root.geometry(f"{WIDTH}x{HEIGHT}+{SCREEN_WIDTH//2 - WIDTH//2}+{SCREEN_HEIGHT//2 - HEIGHT//2}")
ttk.Style().configure("BW.TLabel", foreground="gray")

ttk.Label(root,text = SELF_NAME,font = ("", 20),).pack()
ttk.Label(root,text = MY_IP,font = ("", 11),style="BW.TLabel").pack()

frame = ttk.Frame(root)

frame.pack(side="top", fill="both", expand=True)

ttk.Sizegrip(root).pack(side="right")

usleep = lambda x: sleep(x/1000000.0)
PACKET_SIZE = 1048576

def send_file(ip: str):
    file = askopenfile(mode ='rb')
    if file:
        def thread():
            PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
            FILE_KEY = Fernet.generate_key()
            f = Fernet(FILE_KEY)
            
            name = file.name.split("/")[-1]
            content = file.read()
            content = f.encrypt(content)
            size = len(content)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, 6969))
                s.sendall(json.dumps({"name":name, "size":size}).encode())
                ran = 0
                result = s.recv(1024).decode()
                if int(result):
                    KEY_PUBLIC = s.recv(1024)
                    KEY_PUBLIC = serialization.load_pem_public_key(KEY_PUBLIC)
                    KEY_DECRYPT = KEY_PUBLIC.encrypt(FILE_KEY, PADDING)
                    s.sendall(KEY_DECRYPT)

                    while ran < size:
                        if size-ran >= PACKET_SIZE:
                            a = content[ran:ran+PACKET_SIZE]
                            s.sendall(a)
                            ran+=PACKET_SIZE
                        else:
                            a = content[ran:size]
                            s.sendall(a) 
                            ran+= len(a)
                        usleep(0.1)
        thread = threading.Thread(target=thread)
        thread.daemon = True
        thread.start()

def receive_file():
        """Continuous thread that will wait to receive a file, through TCP."""
        # generate the Private and Public key as we'll need it for the operation
        logging.info("Setting up RSA encryption...")
        PADDING = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None)
        PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=1024,)
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

def udp_send(message: str, ip: str = "255.255.255.255"):
    """Sends a message through UDP. Defaults to broadcast if the IP is not specified."""
    if type(message) == str:
        UDP_IP = ip
        UDP_MESSAGE = message.encode('utf-8')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(UDP_MESSAGE, (UDP_IP, PORT))
    else:
        raise TypeError("Payload in message must be a string.")

def udp_receive():
    """Receive data through UDP, mainly broadcasts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',PORT))
    while True:
        message = sock.recvfrom(512)
        refresh_users(message[0].decode().split(';') + list(message[1]))

def refresh_users(info: list):
    message, name, ip = info[:-1]
    if message == 'Disponible' :
        if not(ip in available_peers) and not(ip == MY_IP):  
            available_peers[ip] = {'name':name,'button':None,'here':True} 

        elif not(ip == MY_IP):
            available_peers[ip]['here'] = True
            available_peers[ip]["name"] = name

def refresh_users_interface():
    trash = []
    no_users = ttk.Label(frame, text="Aucun utilisateur n'est connecté :(", style="BW.TLabel")
    if ("!label" not in frame.children) and (not available_peers):
        no_users.pack(expand=True)
    else:
        no_users.pack_forget()

    for ip in available_peers:          
        if not available_peers[ip]["button"]:
            container = ttk.Frame(frame, padding=5)
            ttk.Separator(container, orient="horizontal").pack(fill="x")
            ttk.Label(container,text = available_peers[ip]["name"],font = ("", 13),).pack(side="left")

            ttk.Label(container,text = ip,font = ("", 9),style="BW.TLabel",).pack(side="left")

            ttk.Button(container, text="Envoyer", command=lambda ip=ip:send_file(ip)).pack(side="right")
            container.pack(fill="x")
            available_peers[ip]["button"] = container
        
        if not available_peers[ip]['here']:
            available_peers[ip]["button"].destroy()
            trash.append(ip)
        
        if available_peers[ip]['here']:
            available_peers[ip]['here'] = False

    for i in trash:
        del available_peers[i]
    
    root.after(500, lambda : refresh_users_interface())

def update_presence():
    udp_send("Disponible;" + SELF_NAME)
    root.after(450, update_presence)

def begin_threads():
    threads = [
        threading.Thread(target=receive_file),
        threading.Thread(target=udp_receive),
    ]

    for thread in threads:
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    update_presence()
    refresh_users_interface()
    begin_threads()
    root.mainloop()