
set passphrase
echo -n "set-passphrase secret" | socat - UNIX-CONNECT:socket

encrypt
cat <(echo 'encrypt file.txt') file.txt | socat - UNIX-CONNECT:socket

NOTE:
After setting the passphare, try to decrypt a file with known content, otherwise typos will not be detected!

Currently, this "leaves the door open" for root in all sessions until the timeout.
Can be improved by:

- set-passphrase receiving a publickey from the server
- encrypts passphrase with it, sends to server
- receives a token to store in ENV
- that token is required to decrypt the stored passphrase
(needs multiple passphrase/token slots in the service)

