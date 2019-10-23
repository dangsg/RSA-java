Create plaintext.txt file as plaintext.

Private key will be saved in privateKey.txt

Public key will be saved in publicKey.txt

Ciphertext will be saved in ciphertext.txt

Deciphertext will be saved in deciphertext.txt

Compile:
javac -cp commons-codec-1.13/*:. RSA.java

Generate keys:
java -cp commons-codec-1.13/*:. RSA.java genkey

Encrypt:
java -cp commons-codec-1.13/*:. RSA.java encrypt

Decrypt:
java -cp commons-codec-1.13/*:. RSA.java decrypt
