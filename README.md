# combocrypt-cmd
ComboCrypt is a high-strength asymmetrical encryption scheme

combocrypt-cmd provides a command-line tool to encrypt/decrypt files with ComboCrypt

### Cloning
```
git clone --recursive https://github.com/samrankin1/combocrypt-cmd.git
```

&nbsp;
### Usage Tutorial

#### Generating keys:
Before sending or receiving encrypted files, one must generate a personal key pair.
```
python combocrypt-cmd.py --mode generate --output [mykey]
```
or
```
python combocrypt-cmd.py -g -o [mykey]
```

#### Sending a file:
To send a file to someone, they must first provide you with a copy of their **public** key (*.pubkey*) -- after that, you can encrypt files that only they will be able to decrypt.
```
python combocrypt-cmd.py --mode encrypt --key [theirkey] --input [secret.txt]
```
or
```
python combocrypt-cmd.py -e -k [theirkey] -i [secret.txt]
```
This will create a file with the *.enc* file extension; in this case, *secret.txt.enc*, which you can send to the recipient via any means. The contents cannot be read or altered in transit, and only the holder of the recipient's key may decrypt it.

#### Receiving a file:
To receive an encrypted file, the sender must provide you with a *.enc* file that was made out to *your* public key. To decrypt the file, you must your your **private** key.
```
python combocrypt-cmd.py --mode decrypt --key [mykey] --input [secret.txt.enc]
```
or
```
python combocrypt-cmd.py -d -k [mykey] -i [secret.txt.enc]
```
This will restore the file to its original condition, placing a copy in the local directory.
