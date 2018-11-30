from random import choice
import string
import sys
from Crypto.Cipher import AES
from Crypto import Random

# generate random key of length n
# just grabs a random hexidecimal character
def gen_random_key(n):
    k = []
    for i in range(n):
        k.append(choice(['0', '1']))
    return k

# Simply writes some text to the given file/file path
def write_cipher_text_to_file(filePath, text):
    cipher_text = open(filePath, "w")
    cipher_text.write(text)
    cipher_text.close()

# Same as above, isn't actually necessary to have two, but I don't feel like fixing it
def write_decoded_text_to_file(filePath, text):
    decoded_text = open(filePath, "w")
    decoded_text.write(text)
    decoded_text.close()

def main():
    # get user input arguments
    input = sys.argv

    if len(input) == 1:
        print("Arguments are required, running default encryption. For future reference: use enc, dec, or keygen")
        enc("data/key.txt", "data/plaintext.txt", "data/ciphertext.txt")
        return

    # depending on the arguments we'll need to enc, dec or generate a keygen accordingly
    if input[1] == "enc":
        enc(input[2], input[3], input[4])
    elif input[1] == "dec":
        dec(input[2], input[3], input[4])
    elif input[1] == "keygen":
        keygen(input[2], input[3])
    else:
        print("Invalid command: Use enc, dec, or keygen")

# Handles encoding of text plain_text given a key key and output file cipher_text
def enc(key_fp, plain_text_fp, cipher_text_fp):
    # open both key and plain_text files
    key_text  = open(key_fp, "r")
    plain_text  = open(plain_text_fp, "r").read()

    # if the length isn't 16, just add some spaces at the end until it is
    while(len(plain_text) % 16 != 0): 
        plain_text = plain_text + " "

    # Generate an instantiation vector
    iv = Random.new().read(AES.block_size)

    # Write iv to file
    iv_text = open("data/iv.txt", "w")
    # First convert the iv to hex so its humanly readable
    iv_text.write(''.join(iv.hex()))
    iv_text.close()

    # create new aes encryption method using given key and iv
    aes = AES.new(key_text.read().encode("utf8"), AES.MODE_CBC, iv)
    # encrypt plain_text using newly created aes encryptor, note that plain_text must first be converted to bytes
    cipher_text = aes.encrypt(plain_text.encode("utf8"))
    # again, write to file after converting to hex
    write_cipher_text_to_file(cipher_text_fp, cipher_text.hex())

    print(cipher_text.hex())

# Handles decoding of text cipher_text given a key key and output file result_text
def dec(key, cipher_text_fp, result_text):
    # open both key and plain_text files
    key_text  = open(key, "r").read()
    cipher_text = open(cipher_text_fp, "r").read()
    iv_text = open("data/iv.txt", "r").read()

    # iv will be in hex, aes expects bytes so convert it back
    iv_bytes = bytes.fromhex(iv_text)
    
    aes = AES.new(key_text.encode("utf8"), AES.MODE_CBC, iv_bytes)
    # like the iv plain_text is in hex, needs to be in bytes
    plain_text = aes.decrypt(bytes.fromhex(cipher_text))
    write_decoded_text_to_file(result_text, plain_text.decode())

    print(plain_text.decode())

# generates a new key of length length and outputs it to file new_key_text
def keygen(prf_key_file_name, aes_key_file_name):
    length = 256
    keyPRF = gen_random_key(length)
    keyAES = gen_random_key(length)
    print('PRF Key:' + ''.join(keyPRF))
    print('AES Key: ' + ''.join(keyAES))

    key_text_PRF = open(prf_key_file_name, "w")
    key_text_PRF.write(''.join(keyPRF))
    key_text_PRF.close()

    key_text_AES = open(aes_key_file_name, "w")
    key_text_AES.write(''.join(keyAES))
    key_text_AES.close()

main()