# Snapdroupe
This app was made as a high school project in collaboration with [mistpelled](https://github.com/mistpelled) and [Ailron](https://github.com/Ailron).

It's supposed to be a local file-sharing app (with encryption!).  
Something similar to Snapdrop/Pairdrop, except it has the advantage of being functional without any internet connection. Ok, the disadvantages are that it's probably slower, not as stable and doesn't support as many platforms...**but that's not the point**.

The point is that we're pretty proud of the project and had a lot of fun working on it (plus we got a good grade, definitely worth it)!

### How does it work?  
Basically, when the app is launched it uses threading to continuously:
- Broadcast a message to show that it's alive, every 450ms (UDP)
- Listen to check for other users (UDP)
- Wait to receive a file (TCP)

When someone eventually decides to send a file, the receiver gets the name and size of the file, which triggers a confirmation dialog.  
If the transfer is accepted, the receiver sends its RSA (asymmetric encryption algorithm) public key to the sender.  
The file is then encrypted using Fernet (symmetric encryption algorithm) and the public key from earlier is used to encrypt and send the Fernet key back to the receiver.
The receiver now has all it needs to handle the data it will receive, so the file transfer can begin.
