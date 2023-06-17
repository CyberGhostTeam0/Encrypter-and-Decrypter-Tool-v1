import base64
import colorama
from colorama import Fore, Style

# BİNARY 
def binary_encode():
    mesaj = input("Şifreliyeceğiniz metini girin: ")
    print(Fore.MAGENTA)
    binary = " ".join(format(ord(c), "b") for c in mesaj)
    print("Çözülmüş Metin: " + binary)

def binary_decode():
    sifreli_metin = input("Şifresini çözeceğiniz metin girin: ")
    print(Fore.MAGENTA)
    decode = "".join(chr(int(c, 2)) for c in sifreli_metin.split(" "))
    print("Şifrelenmiş Metin: "+decode)
    


#HEXADECIMAL
def encode_hexadecimal():
    message = input("Encode etmek istediğiniz metni buraya girin: ")
    print(Fore.MAGENTA)
    encoded_message = message.encode("utf-8").hex()
    print("Encoded: " + encoded_message)

def decode_hexadecimal():
    encoded_message = input("Decode etmek istediğiniz hexadecimal metni buraya girin: ")
    print(Fore.MAGENTA)
    decoded_message = bytes.fromhex(encoded_message).decode("utf-8")
    print("Decoded: " + decoded_message)



#SEZAR
def sifrele():
    anahtar = int(input("Anahtarı giriniz: "))
    sifrelenicek_metin = input("Şifrelenecek metni giriniz: ")
    print(Fore.MAGENTA)
    sifrelenmis = ''.join(chr(ord(i) + anahtar) for i in sifrelenicek_metin)
    print(sifrelenmis)


def cöz():
    anahtar = int(input("Anahtar dizisini giriniz: "))
    sifreli_metin = input("Şifreli metni giriniz: ")
    print(Fore.MAGENTA)
    çözülmüş = ''.join(chr(ord(i) - anahtar) for i in sifreli_metin)
    print(çözülmüş)



#MORSE
def encode_morse():
    message = input("Şifrelemek istediğiniz metni girin: ")
    morse_code = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....',
        'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.',
        'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.'
    }
    print(Fore.MAGENTA)

    encoded_message = []
    for char in message.upper():
        if char in morse_code:
            encoded_message.append(morse_code[char])
    encoded_text = ' '.join(encoded_message)
    print("Şifrelenmiş Metin: " + encoded_text)



def decode_morse():
    message = input("Çözümlemek istediğiniz morse kodunu girin: ")
    morse_code = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
        '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
        '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
        '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'
    }
    print(Fore.MAGENTA)

    morse_list = message.split(' ')
    decoded_message = ''
    for morse_char in morse_list:
        if morse_char in morse_code:
            decoded_message += morse_code[morse_char]
    print("Çözümlenmiş Metin: " + decoded_message)





#BASE64
def base64_encode():
    text = input("Şİfrelenilecek Metni giriniz: ")
    print(Fore.MAGENTA)    
    encoded_bytes = base64.b64encode(text.encode('utf-8'))
    encoded_text = encoded_bytes.decode('utf-8')
    print("Kodlanmış metin:", encoded_text)
    

def base64_decode():
    text = input("ÇÖzülücek Metni giriniz: ")
    print(Fore.MAGENTA)
    decoded_bytes = base64.b64decode(text.encode('utf-8'))
    decoded_text = decoded_bytes.decode('utf-8')
    print("Kod çözülmüş metin:", decoded_text)





# XOR encode işlemi
def xor_encode():
    message = input("Metni giriniz: ")
    key = input("Anahtarı giriniz: ") #key string bir değerde olabilir integer değer de
    
    print(Fore.MAGENTA)
    encrypted_message = ""
    for i in range(len(message)):
        encrypted_message += chr(ord(message[i]) ^ ord(key[i % len(key)]))
    
    print("Şifrelenmiş metin:", encrypted_message)




# XOR encode işlemi
def xor_decode():
    encrypted_message = input("Şifrelenmiş metni giriniz: ")
    key = input("Anahtarı giriniz: ") #girilen anahtar değeri aynı olmalı encrypteki ile

    print(Fore.MAGENTA)
    decrypted_message = ""
    for i in range(len(encrypted_message)):
        decrypted_message += chr(ord(encrypted_message[i]) ^ ord(key[i % len(key)]))
    
    print("Çözülmüş metin:", decrypted_message)




#ROT13 ŞİFRELEME
def rot13_decode_encode():
    def rot13_encode(message):
        encoded_message = ""
        for char in message:
            if char.isalpha():
                if char.islower():
                    encoded_char = chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                else:
                    encoded_char = chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                encoded_char = char
            encoded_message += encoded_char

        return encoded_message

    def rot13_decode(message):
        return rot13_encode(message)

    # ROT13 encode işlemi
    def encode():
        message = input("şifreleyeceğiniz Metni giriniz: ")
        encoded_message = rot13_encode(message)
        print("Şifrelenmiş metin:", encoded_message)

    # ROT13 decode işlemi
    def decode():
        message = input("çözeceğiniz Metni giriniz: ")
        decoded_message = rot13_decode(message)
        print("Çözülmüş metin:", decoded_message)

    # ROT13 encode veya decode işlemi seçimi
    operation = input("1-) ENCODE\n2-) DECODE\nYapmak istediğiniz işlemi seçin (1/2): ")

    print(Fore.MAGENTA)
    if operation == "1":
        encode()
    elif operation == "2":
        decode()
    else:
        print("Geçersiz işlem seçimi!")




#REVERSE ALGORİTMASI
def reverse_encode():
    sozcuk = input("Metni giriniz: ")
    liste = []

    for i in sozcuk:
            liste.append(i)
        
    liste.reverse()
    sifreli_metin = ""

    for i in liste:
        sifreli_metin += i

    print("şifrelenmiş Metin: " + sifreli_metin)

def reverse_decode():
     sozcuk = input("şifreli metni giriniz: ")
     liste = []

     for i in sozcuk:
          liste += i
     
     liste.reverse()
     şifrelenmiş_metin = ""

     for i in liste:
        şifrelenmiş_metin += i

     print("Deşifrenlenmiş Metin: " + şifrelenmiş_metin)



#RAİL FENCE ALGORİTMASI
import re

def rail_encryption():
    msg = input("Mesajı giriniz: ")
    rails = int(input("Ray sayısını giriniz: "))

    # removing white space from message
    msg = msg.replace(" ", "")

    # creating an empty matrix
    railMatrix = []
    for i in range(rails):
        railMatrix.append([])
    for row in range(rails):
        for column in range(len(msg)):
            railMatrix[row].append('.')


    row = 0
    check = 0
    for i in range(len(msg)):
        if check == 0:
            railMatrix[row][i] = msg[i]
            row += 1
            if row == rails:
                check = 1
                row -= 1
            # inner if
        elif check == 1:
            row -= 1
            railMatrix[row][i] = msg[i]
            if row == 0:
                check = 0
                row = 1
    print(Fore.GREEN)

    encryp_text = ""
    for i in range(rails):
        for j in range(len(msg)):
            encryp_text += railMatrix[i][j]
    # for

    # removing '.' from encrypted text
    encryp_text = re.sub(r"\.", "", encryp_text)
    print("Encrypted Text: {}".format(encryp_text))


def rail_decryption():
    msg = input("Metni giriniz: ")
    rails = int(input("Ray sayısını giriniz: "))

    # removing white space from message
    msg = msg.replace(" ", "")

    # creating an empty matrix
    railMatrix = []
    for i in range(rails):
        railMatrix.append([])
    for row in range(rails):
        for column in range(len(msg)):
            railMatrix[row].append('.')

    row = 0
    check = 0
    for i in range(len(msg)):
        if check == 0:
            railMatrix[row][i] = msg[i]
            row += 1
            if row == rails:
                check = 1
                row -= 1
                # inner if
        elif check == 1:
            row -= 1
            railMatrix[row][i] = msg[i]
            if row == 0:
                check = 0
                row = 1

    # reordering the matrix
    ordr = 0
    for i in range(rails):
        for j in range(len(msg)):
            temp = railMatrix[i][j]
            if re.search("\\.", temp):
                # skipping '.'
                continue
            else:
                railMatrix[i][j] = msg[ordr]
                ordr += 1

    print(Fore.GREEN)

    # testing matrix reorder
    for i in railMatrix:
        for column in i:
            print(column, end="")
        #inner for
        print("\n")
    # for

    check = 0
    row = 0
    decryp_text = ""
    for i in range(len(msg)):
        if check == 0:
            decryp_text += railMatrix[row][i]
            row += 1
            if row == rails:
                check = 1
                row -= 1
            # inner if
        elif check == 1:
            row -= 1
            decryp_text += railMatrix[row][i]
            if row == 0:
                check = 0
                row = 1

    decryp_text = re.sub(r"\.", "", decryp_text)
    print("Decrypted Text: {}".format(decryp_text))


def main():
    choice = int(input("1. Encryption\n2. Decryption\nseç(1,2): "))
    if choice == 1:
        print("---Encryption---")
        rail_encryption()
    elif choice == 2:
        print("---Decryption---")
        rail_decryption()
    else:
        print("Invalid Choice")



#ATBASH ALGORİTMASI
def at_encryption():
    alpa = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # reversing alphabets of alpa variable
    rev_alpa = alpa[::-1]
    print(Fore.GREEN)

    message = input("Metni giriniz: ").upper();

    encry_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            encry_text += " "
        else:
            for j in range(len(alpa)):
                if message[i] == alpa[j]:
                    encry_text += rev_alpa[j]
                    break
    
    print(Fore.MAGENTA)
    print("Encrypted Text: {}".format(encry_text))


def at_decryption():
    alpa = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # reversing alphabets of alpa variable
    rev_alpa = alpa[::-1]
    print(Fore.GREEN)

    message = input("Metni giriniz: ").upper();

    dencry_text = ""

    for i in range(len(message)):
        if message[i] == chr(32):
            dencry_text += " "
        else:
            for j in range(len(rev_alpa)):
                if message[i] == rev_alpa[j]:
                    dencry_text += alpa[j]
                    break
    print(Fore.MAGENTA)
    print("Decrypted Text: {}".format(dencry_text))



def atbash_algortihm():
    choice = int(input("1.Encryption\n2.Decryption\nseçim(1,2): "))
    if choice == 1:
        print("---Encryption---")
        at_encryption()
    elif choice == 2:
        print("---Decryption---")
        at_decryption()
    else:
        print("Wrong Choice")





#ROT-47 ŞİFRELEME
def rot47_encryption():
    message = input("Enter message: ")
    key = 47
    encryp_text = ""

    for i in range(len(message)):
        temp = ord(message[i]) + key
        if ord(message[i]) == 32:
            encryp_text += " "
        elif temp > 126:
            temp -= 94
            encryp_text += chr(temp)
        else:
            encryp_text += chr(temp)
        # if-else
    # for

    print("Encrypted Text: {}".format(encryp_text))


def rot47_decryption():
    message = input("Enter message: ")
    key = 47
    decryp_text = ""

    for i in range(len(message)):
        temp = ord(message[i]) - key
        if ord(message[i]) == 32:
            decryp_text += " "
        elif temp < 32:
            temp += 94
            decryp_text += chr(temp)
        else:
            decryp_text += chr(temp)

    print("Decrypted Text: {}".format(decryp_text))


def rot47_encryp_decrpt():
    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print(Fore.MAGENTA)
        print("---Encryption---")
        rot47_encryption()
    elif choice == 2:
        print(Fore.MAGENTA)
        print("---Decryption---")
        rot47_decryption()
    else:
        print("Invalid Choice")



#Vigenère ALGORİTMASI
def vigenere_encryption():
    msg = input("Şifreleyeceğiniz Metni girin: ").replace(" ", "").upper()
    # print(msg)
    key = input("Anahtarı girin(str/int): ").upper()

    # assigning numbers to keywords
    kywrd_num_list = keyword_num_assign(key)

    # printing key
    for i in range(len(key)):
        print(key[i], end=" ", flush=True)
    # for
    print()
    for i in range(len(key)):
        print(str(kywrd_num_list[i]), end=" ", flush=True)
    # for
    print()
    print("-------------------------")

    # in case characters don't fit the entire grid perfectly.
    extra_letters = len(msg) % len(key)
    # print(extraLetters)
    dummy_characters = len(key) - extra_letters
    # print(dummyCharacters)

    if extra_letters != 0:
        for i in range(dummy_characters):
            msg += "."

    num_of_rows = int(len(msg) / len(key))

    # Converting message into a grid
    arr = [[0] * len(key) for i in range(num_of_rows)]
    z = 0
    for i in range(num_of_rows):
        for j in range(len(key)):
            arr[i][j] = msg[z]
            z += 1

    for i in range(num_of_rows):
        for j in range(len(key)):
            print(arr[i][j], end=" ", flush=True)
        print()

    num_loc = get_number_location(key, kywrd_num_list)

    print(num_loc)

    # cipher
    cipher_text = ""
    k = 0
    for i in range(num_of_rows):
        if k == len(key):
            break
        else:
            d = int(num_loc[k])
        for j in range(num_of_rows):
            cipher_text += arr[j][d]
        k += 1


    print("şifrelenmiş metin: {}".format(cipher_text))


def get_number_location(key, kywrd_num_list):
    num_loc = ""
    for i in range(len(key) + 1):
        for j in range(len(key)):
            if kywrd_num_list[j] == i:
                num_loc += str(j)

    return num_loc


def keyword_num_assign(key):
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    kywrd_num_list = list(range(len(key)))
    # print(kywrdNumList)
    init = 0
    for i in range(len(alpha)):
        for j in range(len(key)):
            if alpha[i] == key[j]:
                init += 1
                kywrd_num_list[j] = init

    return kywrd_num_list


def vigenere_decryption():
    msg = input("Şifreli metni giriniz: ").replace(" ", "").upper()
    # print(msg)
    key = input("Anahtarı giriniz(str/int): ").upper()

    # assigning numbers to keywords
    kywrd_num_list = keyword_num_assign(key)

    num_of_rows = int(len(msg) / len(key))

    # getting locations of numbers
    num_loc = get_number_location(key, kywrd_num_list)

    # Converting message into a grid
    arr = [[0] * len(key) for i in range(num_of_rows)]

    # decipher
    plain_text = ""
    k = 0
    itr = 0


    for i in range(len(msg)):
        d = 0
        if k == len(key):
            k = 0
        else:
            d: int = int(num_loc[k])
        for j in range(num_of_rows):
            arr[j][d] = msg[itr]
            itr += 1
        if itr == len(msg):
            break
        k += 1
    print()

    for i in range(num_of_rows):
        for j in range(len(key)):
            plain_text += str(arr[i][j])

    print("Çözülmüş metin: " + plain_text)


def Vigenère():
    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print(Fore.GREEN)
        print("Encryption")
        vigenere_encryption()
    elif choice == 2:
        print(Fore.GREEN)
        print("Decryption")
        vigenere_decryption()
    else:
        print("Invalid Choice")


#ROT-5 (SADECE İNTEGER DEĞERLERİ ŞİFRLEER) 
import sys

def cipher_encryption(rot5, zero_to_nine):
    message = input("mesajı giriniz(Tam Sayı Girmelisiniz): ")

    # checking if input is int or not
    if not re.search('[\d\s]+', message):
        print("Tam sayı değeri girmelisiniz: ")
        sys.exit()
 

    encryp_text = ""
    for i in range(len(message)):
        if message[i] == chr(32):
            encryp_text += " "
        else:
            for j in range(len(zero_to_nine)):
                # simple substitution
                if message[i] == zero_to_nine[j]:
                    encryp_text += rot5[j]

    print("Encrypted Text: {}".format(encryp_text))


def cipher_decryption(rot5, zero_to_nine):
    message = input("metni giriniz(Tam Sayı Girmelisiniz): ")

    # checking if input is int or not
    if not re.search('[\d\s]+', message):
        print("Tam sayı girmelisiniz: ")
        sys.exit()


    decryp_text = ""
    for i in range(len(message)):
        if message[i] == chr(32):
            decryp_text += " "
        else:
            for j in range(len(zero_to_nine)):
                # simple substitution
                if message[i] == rot5[j]:
                    decryp_text += zero_to_nine[j]

    print("Encrypted Text: {}".format(decryp_text))


def rot5():
    rot5 = "5678901234"
    zero_to_nine = "0123456789"

    choice = int(input("1. Encryption\n2. Decryption\nChoose(1,2): "))
    if choice == 1:
        print("---Encryption---")
        cipher_encryption(rot5, zero_to_nine)

    elif choice == 2:
        print("---Decryption---")
        cipher_decryption(rot5, zero_to_nine)

    else:
        print("Wrong Choice")







while True:
    colorama.init()

    print(Fore.MAGENTA)

    print('                     CYBER GHOST TEAM 2023\n                       SILENT AS A GHOST')

    print(Style.RESET_ALL)
    print(Fore.RED)

    print('''
    ---------------------------------------------------------------
    |                                                             |                                             DISCORD:
    |     / ________|  / __________|  |__________|                |                                             LINK 1 = https://discord.gg/cyberghostteam
    |    | |          | |  _______       |  |                     |                                             LINK 2 = https://discord.gg/2kcZzYFXQf
    |    | |          | |  |______\      |  |                     |
    |    | |_______   | |_______| |      |  |                     |                      
    |    \_________|  \___________|      |__|                     |                               
    |                                                             |                  by WEXTER & HERAX
     --------------------------------------------------------------
    ''')

    

    print(Fore.MAGENTA)
    print("1 ----> BİNARY \n2 ----> HEXADECIMAL \n3 ----> SEZAR \n4 ----> MORSE \n5 ----> BASE64 \n6 ----> XOR\n7 ----> ROT-13\n8 ----> ROT-47\n9 ----> RAİL FENCE\n10 ---> ATBASH\n11 ---> REVERSE\n12 ---> Vigenère\n13 ---> ROT-5\n")
    print(Fore.CYAN)

    algoritma = int(input("KULLANACAĞINIZ ALGORİTMAYI SEÇİN (1,2,3,4,5,6,7,8,9,10,11,12,13): "))

    print(Fore.YELLOW)

    #BİNARY ALGORİTMASI
    if algoritma == 1:
        x = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2): "))
        if x == 1:
            print(Fore.GREEN + "\n")
            binary_encode()

        elif x == 2: 
            print(Fore.GREEN + "\n")
            binary_decode()

   
    #HEXADECIMAL ALGORİTMASI
    elif algoritma == 2:
        y = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2): "))
        if y == 1:
            print(Fore.GREEN + "\n")
            encode_hexadecimal()

        elif y == 2:
            print(Fore.GREEN + "\n")
            decode_hexadecimal()


    #SEZAR ALGORİTMASI
    elif algoritma == 3:
        z = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2): "))
        if  z == 1:
            print(Fore.GREEN)
            sifrele()

        elif z == 2:
            print(Fore.GREEN)
            cöz()
            

    #MORSE ALGORİTMASI
    elif algoritma == 4:
        w = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2):"))
        if w == 1:
            print(Fore.GREEN)
            encode_morse()        
        
        elif w == 2:
            print(Fore.GREEN)
            decode_morse()

            
    #BASE64 ALGORİTMASI
    elif algoritma == 5:
        q = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2):"))
        if q == 1:
            print(Fore.GREEN)
            base64_encode()

        elif q == 2:
            print(Fore.GREEN)
            base64_decode()


    #XOR ALGORİTMASI
    elif algoritma == 6:
        a = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2):"))
        if a == 1: 
            print(Fore.GREEN)
            xor_encode()

        elif a == 2:
            print(Fore.GREEN)    
            xor_decode()

    #ROT13
    elif algoritma == 7:
        rot13_decode_encode()

    #REVERSE
    elif algoritma == 11:  #rot47 ile reverse yer değişti.
        b = int(input("1-) ENCRYPT\n2-) DECRYPT \n-Decrypt mi Encrypt mi edeceksiniz(1,2):"))
        if b == 1:
            print(Fore.GREEN)
            reverse_encode()        

        elif b == 2:
            print(Fore.GREEN)
            reverse_decode()
    
    #RAIL FENCE
    elif algoritma == 9: 
        main() #main = rail fence
 
    #ATBASH
    elif algoritma == 10:
        atbash_algortihm()

    elif algoritma == 8: #rot47 ile reverse yer değişti.
        rot47_encryp_decrpt()


    elif algoritma == 12:
        Vigenère()

    elif algoritma == 13:
        rot5()
        
    else:
        print("HATALI İŞLEM")
    
    print(Fore.CYAN)
    cikis = int(input("\n\n1-)EVET\n2-)HAYIR\n-Çıkmak istiyor musunuz(1,2): "))
    if cikis == 1:
        break

    elif cikis == 2:
        continue
