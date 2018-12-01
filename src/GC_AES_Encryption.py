from random import choice
import string
import sys
import os
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
        enc(input[2], input[3], input[4], input[5], input[6])
    elif input[1] == "dec":
        dec(input[2], input[3], input[4])
    elif input[1] == "keygen":
        keygen(input[2], input[3])
    elif input[1] == "token":
        generate_token(input[2], input[3], input[4])
    else:
        print("Invalid command: Use enc, dec, or keygen")

def generate_token(keyword, key_PRF_filepath, token_filepath):
    key_PRF_file_text = open(key_PRF_filepath, "r").read()
    token_file = open(token_filepath, "w")
    token_file.write(encrypt_string_with_PRF(keyword, key_PRF_file_text).hex())

# Handles encoding of text plain_text given a key key and output file cipher_text
def enc(key_PRF_filepath, key_AES_filepath, index_filepath, files_folderpath, ciphertextfiles_folderpath):
    filenames_with_keywords_dictionary = {}
    
    # Get file names and keyword arrays, insert into dictionary
    for filename in os.listdir(files_folderpath):
        if filename.endswith(".txt"):
            keywords_array = get_keywords_from_file(files_folderpath + "/" + filename)
            filenames_with_keywords_dictionary[filename] = keywords_array
    
    print(filenames_with_keywords_dictionary)

    key_PRF_file_text = open(key_PRF_filepath, "r").read()
    key_AES_file_text = open(key_AES_filepath, "r").read()

    unique_keyword_set = set()
    for filename, keywords_array in filenames_with_keywords_dictionary.items():
        for word in keywords_array:
            unique_keyword_set.add(word)

    #print(encrypt_string_with_PRF(filename, key_PRF_file_text))
    print(unique_keyword_set)

    unencrypted_inverted_index_dictionary = {}
    for keyword in unique_keyword_set:
        files_with_this_keyword_set = set()
        for filename, keywords_array in filenames_with_keywords_dictionary.items():
            for word in keywords_array:
                if(word == keyword):
                    files_with_this_keyword_set.add(filename)
        unencrypted_inverted_index_dictionary[keyword] = files_with_this_keyword_set
    
    print(unencrypted_inverted_index_dictionary)

    # count = 1
    # for filename, keywords_array in filenames_with_keywords_dictionary.items():
    #     if int(filename[1]) == count:
    #         cipher_text = open(ciphertextfiles_folderpath + "/" + "c" + str(count) + ".txt", "w")
    #         for keyword in keywords_array:
    #             cipher_text.write(encrypt_string_with_PRF(keyword, key_PRF_file_text).hex())
    #             cipher_text.write(" ")
    #         cipher_text.close()
    #     count = count + 1

    encrypted_inverted_index_dictionary = {}
    for keyword in unique_keyword_set:
        files_containing_keyword_array = unencrypted_inverted_index_dictionary[keyword]
        ciphertext_files_containing_keyword_array = []
        for filename in files_containing_keyword_array:
            cipher_text_filename = filename.replace("f", "c")
            cipher_text = open(ciphertextfiles_folderpath + "/" + cipher_text_filename, "w")
            for word in filenames_with_keywords_dictionary[filename]:
                cipher_text.write(encrypt_string_with_AES(word, key_AES_file_text).hex())
                cipher_text.write(" ")
            cipher_text.close()
            ciphertext_files_containing_keyword_array.append(cipher_text_filename)
        encrypted_unique_keyword = encrypt_string_with_PRF(keyword, key_PRF_file_text).hex()
        encrypted_inverted_index_dictionary[encrypted_unique_keyword] = ciphertext_files_containing_keyword_array

    print(encrypted_inverted_index_dictionary)
    
    # open both key and plain_text files
    key_text  = open(key_PRF_filepath, "r")

    # create new aes encryption method using given key and iv
    aes = AES.new(key_text.read().encode("utf8"), AES.MODE_CBC, iv)
    # encrypt plain_text using newly created aes encryptor, note that plain_text must first be converted to bytes
    cipher_text = aes.encrypt("hat".encode("utf8"))
    # again, write to file after converting to hex
    write_cipher_text_to_file(cipher_text_fp, cipher_text.hex())

    print(cipher_text.hex())

def get_keywords_from_file(keywords_filepath):
    keywords_array = []
    keywords_text = open(keywords_filepath).read()
    for word in keywords_text.split():
        keywords_array.append(word)

    return keywords_array

def encrypt_string_with_PRF(string_to_encrypt, key_text_to_encrypt_with):
    l = len(string_to_encrypt)

    while(l%16 != 0):
        string_to_encrypt = string_to_encrypt + "0"
        l = len(string_to_encrypt)

    aes = AES.new(key_text_to_encrypt_with.encode("utf-8"), AES.MODE_ECB)
    encrypted_string = aes.encrypt(string_to_encrypt.encode("utf-8"))

    return encrypted_string

def encrypt_string_with_AES(string_to_encrypt, key_text_to_encrypt_with):
    l = len(string_to_encrypt)

    while(l%16 != 0):
        string_to_encrypt = string_to_encrypt + "0"
        l = len(string_to_encrypt)

    aes = AES.new(key_text_to_encrypt_with.encode("utf-8"), AES.MODE_CBC)
    encrypted_string = aes.encrypt(string_to_encrypt.encode("utf-8"))

    return encrypted_string

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
    length = 32
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