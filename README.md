# Chat
An END to END encrypted P2P chat system that uses emial validation and mysql for keeping track of users.
# Cryptography
  - Rsa algorithm for signature and validation
  - Dh for handshaking and sharing a symmetric private key
  - Aes 256 for symmetric encryption
  - Sha 512 as hash function
# Help
- It is assumed the server public key is known as a .pem file somewhere.
- Program is not complete it needs a location for config and priavate and public keys somewhere on the system.
- Some public and priavet keys and shared parameters are provided with the code.
- Server needs an email server to use in order to send the tokens to users
- The database is a simple user mysql database.
