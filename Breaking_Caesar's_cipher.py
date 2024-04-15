"""
This project implements a Caesar cipher encoder/decoder and
code breaker that breaks any encrypted message by finding a known word in it.

This project is based on a project "Breaking Caesar's cipher" from the datawars website
"""
import string
import random
import re


def shift_letters(letters, shift):
    """
    The shift_letters function receives two parameters:
    letters: containing an alphabet, and
    shift: indicating the number of positions to shift (either right or left depending if the number is positive or negative)
    and returns a list of the letters variable shifted.
    """
    shift = shift % len(letters)
    return letters[shift:] + letters[:shift]


def encrypt_full(text, shift):
    """
    Function encrypt_full that will receive ANY text and the shift and encrypt it. 
    Encrypt only ASCII chars. Anything else, remain "intact" (unencrypted).
    """
    upper_letters_old = list(string.ascii_uppercase)
    upper_letters_new = shift_letters(upper_letters_old, shift)
    
    lower_letters_old = list(string.ascii_lowercase)
    lower_letters_new = shift_letters(lower_letters_old, shift)
    
    word_new = ''
    
    for letter in text:
        if letter.isalpha():
            
            if letter.isupper():
                old_index = upper_letters_old.index(letter)
                word_new += upper_letters_new[old_index]
            else:
                old_index = lower_letters_old.index(letter)
                word_new += lower_letters_new[old_index]
        else:
            word_new += letter

    return word_new


def decrypt_full(encrypted_text, original_shift):
    """
    The function decrypt_full receives the encrypted text and the original shift, and returns the unencrypted version.
    """
    upper_letters_old = list(string.ascii_uppercase)
    upper_letters_new = shift_letters(upper_letters_old, original_shift)
    
    lower_letters_old = list(string.ascii_lowercase)
    lower_letters_new = shift_letters(lower_letters_old, original_shift)
    
    word_new = ''
    
    for letter in encrypted_text:
        if letter.isalpha():
            
            if letter.isupper():
                new_index = upper_letters_new.index(letter)
                word_new += upper_letters_old[new_index]
            else:
                new_index = lower_letters_new.index(letter)
                word_new += lower_letters_old[new_index]
        else:
            word_new += letter

    return word_new


def count_distances_between_letters(word):
    """
    The function calculates and returns an array of distances between adjacent letters of a word 
    (the distance is calculated in forward alphabetical order for uppercase letters).
    """
    letters = list(string.ascii_uppercase)
    distances = []
    
    for i in range(len(word)-1):
        first_letter = word[i]
        second_letter = word[i+1]
        
        index_first_letter = letters.index(first_letter)
        index_second_letter = letters.index(second_letter)
        
        distance = index_second_letter - index_first_letter
        
        if distance<0:
            distance += len(letters)
        
        distances.append(distance)
    
    return distances


def clean_string(text):
    """
    Function clean str from all symbols.
    """
    cleaned_text = re.sub(r'[^\w\s]', '', text)
    return cleaned_text


def break_cipher(encrypted_message, known_word):
    """
    The function break_cipher that breaks any encrypted message (encrypted_message) by finding a known word (known_word) in it.
    """
    letters = list(string.ascii_uppercase)
    encrypted_message_upper = encrypted_message.upper()
    encrypted_message_upper_clean = clean_string(encrypted_message_upper)
    message_list = encrypted_message_upper_clean.split()
    
    # create shorter list of words to check out
    message_list_short = []
    for word in message_list:
        if len(word)==len(known_word):
            message_list_short.append(word)
    
    # find encrypt word for known word
    known_word_distances = count_distances_between_letters(known_word)
    
    encrypt_word = ''
    for word in message_list_short:
        if known_word_distances == count_distances_between_letters(word):
            encrypt_word = word
            break
    
    
    # find the shift for our cipher
    known_word_letter = known_word[0]
    encrypt_word_letter = encrypt_word[0]
    index_known_word_letter = letters.index(known_word_letter)
    index_encrypt_word_letter = letters.index(encrypt_word_letter)
    shift = index_encrypt_word_letter - index_known_word_letter
    
    # decrypt step
    result = decrypt_full(encrypted_message, shift)
    return result

if __name__=="__main__":
    print('example of encrypt_full for "DataWars is Great!" with shift=9: ', encrypt_full("DataWars is Great!", 9))
    # example of encrypt_full for "DataWars is Great!" with shift=9:  MjcjFjab rb Panjc!
    print('example of decrypt_full for "MjcjFjab rb Panjc!" with original shift=9: ', decrypt_full("MjcjFjab rb Panjc!", 9))
    # example of decrypt_full for "MjcjFjab rb Panjc!" with original shift=9:  DataWars is Great!
    print('example of count_distances_between_letters for "DATAWARS":', count_distances_between_letters("DATAWARS"))
    # example of count_distances_between_letters for "DATAWARS": [23, 19, 7, 22, 4, 17, 1] 


    print('\n')
    random_shift = random.randint(-100, 100)
    print(f"{random_shift=}")
    encrypted_text = encrypt_full('Datawars: the best data science practice platform, website in the entire world!', random_shift)
    print(f'{encrypted_text=}')
    print('example of break_cipher for encrypted_text:', break_cipher(encrypted_text, "DATAWARS"))


    print('\n')
    random_shift2 = random.randint(-100, 100)
    print(f"{random_shift2=}")
    encrypted_text2 = encrypt_full("I must not fear. Fear is the mind-killer. Fear is the little-death that brings total obliteration. I will face my fear. I will permit it to pass over me and through me. And when it has gone past I will turn the inner eye to see its path. Where the fear has gone there will be nothing. Only I will remain.", random_shift2)
    print(f'{encrypted_text2=}')
    print('example of break_cipher for encrypted_text2:', break_cipher(encrypted_text2, "I"))
    
