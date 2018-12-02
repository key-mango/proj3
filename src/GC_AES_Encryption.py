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
    elif input[1] == "search":
        search(input[2], input[3], input[4], input[5])
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

def search(index_filepath, token_filepath, ciphertextfiles_folderpath, key_AES_filepath):
    token = open(token_filepath, "r").read()
    aes_key = open(key_AES_filepath, "r").read()
    index_text = open(index_filepath, "r").readlines()

    ciphertextfiles_with_keyword = []
    for line in index_text:
        encrypted_keyword = line.split()[0]
        if encrypted_keyword == token:
            for word in line.split():
                if word != token:
                    ciphertextfiles_with_keyword.append(word)

    print(ciphertextfiles_with_keyword)

    for ciphertext_filename in ciphertextfiles_with_keyword:
        text_to_print = ciphertext_filename
        ciphertext = open(ciphertextfiles_folderpath + "/" + ciphertext_filename).read()
        for word in ciphertext.split():
            text_to_print = text_to_print + " " + decrypt_string_with_AES(word, aes_key)
        print(text_to_print)
                

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
    
    index_text = open(index_filepath, "w")
    for encrypted_keyword, filenames in encrypted_inverted_index_dictionary.items():
        index_text.write(encrypted_keyword + " ")
        for filename in filenames:
            index_text.write(filename + " ")
        index_text.write("\n")

    print(encrypted_inverted_index_dictionary)

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
    BLOCK_SIZE = 32
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                    chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    iv = Random.new().read(AES.block_size)

    aes = AES.new(key_text_to_encrypt_with.encode("utf-8"), AES.MODE_CBC, iv)
    encrypted_string = aes.encrypt(pad(string_to_encrypt).encode("utf-8"))

    return encrypted_string

# Handles decoding of text cipher_text given a key key and output file result_text
def decrypt_string_with_AES(string_to_decrypt, key_text_to_decrypt_with):
    string_to_decrypt = bytes.fromhex(string_to_decrypt)
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]

    iv = string_to_decrypt[:AES.block_size]
    aes = AES.new(key_text_to_decrypt_with.encode("utf-8"), AES.MODE_CBC, iv)
    decrypted_string = unpad(aes.decrypt(string_to_decrypt[AES.block_size:])).decode("utf-8")

    return decrypted_string

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