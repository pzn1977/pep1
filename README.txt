*** PEP1 = PZN Encapsulation Protocol - revision 1 ***

 Copyright 2017 Pedro Zorzenon Neto

 SUPPORT ME: https://www.buymeacoffee.com/pzn77

Proposal: encapsulate and transfer data in a simple format, with
strong encryption, CRC error detection, for using with different
physical layers (serial ports, RS485, IP network, etc), able to handle
a server-client topology with a different encryption key for each
client, that can be used in a small processor with less memory and CPU
power than a PC. Not implemented with asymmetric crypto because of its
high CPU requirements.

Each package is composed by 3 "Sections"

First Section => Protocol Identification (aka: MagicNumber)

  4 bytes 0x50 0x65 0x70 0x31 (string "Pep1")

Second Section => Sender Identification (User, Auth, ID, ...)

  4 bytes uint32_t: identification about the user, userID, keyID, authID, ...
  4 bytes uint32_t: payload size (the "n" of "n bytes", see below)
  4 bytes uint32_t: 31-bit random (MSB is always 0, because it is reserved
                                   for protocol revision/extensions)
  4 bytes uint32_t: CRC32 (of previous 12 bytes)

  The second block is encrypted (twofish cipher) with a "COMMON" key,
  that is known to all users.

Third Section => Information/Payload

  1 byte (padding size, value between 0 and 15)
  15 bytes (random bytes to increment entropy)
  n bytes (data / payload)
  0~15 bytes (padding bytes, filled with 0xff)
  4 bytes uint32_t: CRC32 (of previous bytes in this third section)

  The third section size is multiple of 16 bytes. The 0~15 padding
  bytes adjusts this to make the section size multiple of 16.

  The third block is encrypted (twofish cipher) with a "PRIVATE" key,
  that is known only to the server and the user. Other system users do
  not know this key and therefore can not decrypt the third section.

Note: uint32_t are transferred in little endian byte order, that is:
      0x01234567 is transmitted as 0x67 0x45 0x23 0x01

Note: when encrypting sequential blocks of 16 bytes, an XOR operation
      is needed (CBC operation mode). See example:

        (encryption)
        initialize the key
        encrypt(plainblock1)          => enc1
        encrypt(plainblock2 XOR enc1) => enc2
        encrypt(plainblock3 XOR enc2) => enc3
        ...

        (decryption)
        initialize the key
	decrypt(enc1)          => plainblock1
	decrypt(enc2) XOR enc1 => plainblock2
	decrypt(enc3) XOR enc2 => plainblock3
	...

      note that this XOR is only needed for "third section", since it
      is the only section that has more than 1 block.

Usage details:

     * package being sent from client -> server *
       at client:
        - use COMMON key (known to server and all clients)
        - use your own authID
        - use PRIVATE key (the key known to server and your client)
        - encapsulate the data and send
       at server:
        - receive the package
	- get the first and second sections, decrypt with COMMON key
	- you should have authID now, search in some local database for the
	  PRIVATE key of this specific client
	- decrypt the third section with PRIVATE key

     * package being sent from server -> client *
       at server:
        - use the COMMON key
        - use the client authID
        - use the client PRIVATE key
        - encapsulate the data and transmit
       at client:
        - receive the package
	- get the first and second sections, decrypt with COMMON key
	- you should have authID now, check if it matches your own ID
	- decrypt the third section with PRIVATE key
