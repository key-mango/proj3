from random import choice
import sys, random, string
import base64
from Crypto.Cipher import AES
from Crypto import Random

#Encoding function for command line use only
def enc(key_fp, plain_text_fp, cipher_text_fp):
   # open both key and plain_text files
   key_text  = open(key_fp, "r")
   plain_text  = open(plain_text_fp, "r")

   iv = Random.new().read(AES.block_size)

   iv_text = open("data/iv", "w")
   iv_text.write(''.join(iv.hex()))
   iv_text.close()

   aes = AES.new(key_text.read().encode("utf8"), AES.MODE_CBC, iv)

   plaintext = plain_text.read()
   while(len(plaintext) % 16 != 0):
       plaintext = plaintext + " "
   cipher_text = aes.encrypt(plaintext.encode("utf8"))
   write_text_to_file(cipher_text_fp, cipher_text.hex())

#Decoding function for command line use only
def dec(key, cipher_text_fp, result_text):
   # open both key and plain_text files
   key_text  = open(key, "r").read()
   cipher_text = open(cipher_text_fp, "r").read()
   iv_text = open("data/iv", "r").read()

   iv_bytes = bytes.fromhex(iv_text)
   print(bytes.fromhex(iv_text))
  
   aes = AES.new(key_text.encode("utf8"), AES.MODE_CBC, iv_bytes)
   plain_text = aes.decrypt(bytes.fromhex(cipher_text))
   print(plain_text)
   write_text_to_file(result_text, plain_text.decode())

#Generates random key based on given keylength with values 0 or 1
def gen_random_key(n):
   k = []
   for i in range(n):
       k.append(choice(['0', "1"]))
   return k


#Keygen function for command line use
def keygen(file1, file2):
   length = 16
   key1 = gen_random_key(length)
   key2 = gen_random_key(length)
   print(key1 key2)

   key_text1 = open(file1, "w")
   key_text1.write(''.join(key1))
   key_text1.close()

   key_text2 = open(file2, "w")
   key_text2.write(''.join(key2))
   key_text2.close()

#Get IV
def get_initialization_vector():
   k = []
   for i in range(16):
       k.append(ord(choice(['0', "1"])))
   return k


#Write text to file function
def write_text_to_file(file, text):
    with open(file, 'w') as myfile:
        myfile.write(text)
        myfile.close()

#Function to check command line arguments
def input_check():
    input = []
    input = sys.argv
    #print(input)

    if len(sys.argv) == 1:
        return
    elif input[1] == 'enc':
        enc(input[2], input[3], input[4])
    elif input[1] == 'dec':
        dec(input[2], input[3], input[4])
    elif input[1] == 'keygen':
        keygen(input[2], input[3])

#Main function, contains workflow
def main():
    input_check()

    key_text = open('data/key.txt', 'r')
    plain_text = open('data/plaintext.txt', 'r')


main()
