__author__ = "@tccontre18 - Br3akp0int"

import os
import sys
import re
import ctypes
import argparse
import textwrap

"""
description: a small python script tool to de-obfuscate ABOBUS Batch script obfuscator
parameter: a file path or a directory path contains the file to be de-obfuscated
output: it will create a dbobus-output folder that contains the de-obfuscated script
author: @tccontre18 - Br3akp0int
"""

##########################################################################
###GLOBAL VARIABLE
##########################################################################

DEBUG_MODE = 1

ALPHABET = ['C', '\\\\', '\\\\', 'U', 's', 'e', 'r', 's', '\\\\', 'P', 'u', 'b', 'l', 'i', 'c']
PRIVATE_KEY_COUNT = 4
PUBLIC_KEY_COUNT = 1
MAX_FAIL = 0x100
ALPHA_LIST_TABLE = list("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ @=")
DEOBFUS_DIR = "dbobus-output"
##########################################################################
### CLASSES
##########################################################################

####################################
#            settings:             #
class status:
    bom                       = True
    random_at                 = True
    random_semicolon          = True
    random_space              = True #possible crashes
    random_if                 = True
    code_obfuscation          = True
    random_newline            = True #possible crashes
    #cleaning_comments         = True 
    #lower_upper_character     = True
    #function_name_obfuscation = True #this can break the argument system
    #china_symbol              = True
    easy_anti_detect          = True
    anti_detect               = True
    public_enc_key_str        = True
    other_enc_key_str         = True
    decoder_ptn               = b'set "(.+?)=([0-9a-zA-Z@=\s]{65,})"'
####################################


class colors:
    '''Colors class:
    Reset all colors with colors.reset
    Two subclasses fg for foreground and bg for background.
    Use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.green
    Also, the generic bold, disable, underline, reverse, strikethrough,
    and invisible work with the main class
    i.e. colors.bold
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgreen='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'


##########################################################################
### HELPER FUNCTIONS
##########################################################################

def clear_screen():
    # Check if the system is Windows or not
    if os.name == 'nt':
        os.system('cls')  # Windows
    else:
        os.system('clear')  # Linux and macOS

def enable_virtual_terminal_processing():
    # Check if running on Windows
    if os.name == 'nt':
        # Get the handle for the standard output
        handle = ctypes.windll.kernel32.GetStdHandle(-11)
        # Get the current console mode
        mode = ctypes.c_ulong()
        ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode))
        # Enable Virtual Terminal Processing by setting the ENABLE_VIRTUAL_TERMINAL_PROCESSING flag
        mode.value |= 0x0004
        ctypes.windll.kernel32.SetConsoleMode(handle, mode)

def enumerate_files(dir_path):

    for dirs, subdirs, files in os.walk(dir_path):
        for f in files:
            process_file = f"[+] TASK: processing: {f}"
            print(colors.fg.cyan + process_file + colors.reset)
            file_path = os.path.join(dirs, f)

            with open(file_path, "rb") as fr:
                buff = fr.read()
            
            deobfuscation_process(buff, file_path)

    return

def removed_matched_ptn(buff, ptn, replace_val = b""):
    
    buff = re.sub(ptn, replace_val, buff, flags=re.IGNORECASE)

    return buff

def log_ptn_info(buff, ptn):

    # Use re.finditer to find all matches in the buffer
    matches = list(re.finditer(ptn, buff))

    return matches, len(matches)


def log_textview(buff):
    text_wrap = textwrap.fill(buff.decode('utf-8'),width=100)
    return text_wrap

##########################################################################
### DEOBFUSCATOR FUNCTIONS
##########################################################################

def contains_obfuscator(text):
    
    obf1 = list('ﭲسﺖﮚﮱﮕﯔتﮢﯤﺼكﻁﺹﭫ﷽◯')
    obf2 = ['ヾ(⌐■_■)ノ', '(◕‿◕)', '(⊙ω⊙)', '┌( ಠ_ಠ)┘']
    obf3 = list('此訊息已被神秘魔法保護凡人是無法複製貼上這行文字的')

    # Convert bytes to string
    try:
        decode_text = text.decode('utf-8')
    except UnicodeDecodeError:
        try:
            decode_text = text.decode('utf-16-le')
        except UnicodeDecodeError:
            decode_text = ''  # Failed to decode, treat as non-obfuscated
    
    if any(c in decode_text for c in obf1):
        
        return True
    if any(c in decode_text for c in obf2):
        
        return True
    if any(c in decode_text for c in obf3):
        
        return True
    return False


def decode_key_str(buff, encoding_keys):

    start_pos = 0
    ctr=0

    ### pattern for encoded character
    ptn = b"%([^%\s]+?):~(.+?),1%"
    
    
    while True:
        match = re.search(ptn, buff[start_pos:], re.IGNORECASE)
        if not match:
            
            break
        else:
            ### find the match boundaries
            s, e = match.span()

            ### aligned the start and end boundaries in each iteration
            s = s + start_pos
            e = e + start_pos

            ### collect the encoding key name and encoding key value
            var_name = match.group(1)
            indx_val = match.group(2)

            ### check if the key name is in encoding_keys dictionary
            if var_name in encoding_keys:
                
                ### decode it
                decoded_char = encoding_keys[var_name][int(indx_val,10)].to_bytes(1, byteorder='big')
                
                buff = buff[:s] + decoded_char + buff[e:]
                
                ctr = 0
            else:

                ctr+=1 
                if ctr>= MAX_FAIL:
                    break
                else:
                    start_pos = e-1
    

    return buff

def remove_bom(buff):

    if buff[0] == 0xFF or buff [0] == 0xFE:
        buff = buff[4:]
        msg = "[+] TASK: REMOVING BOM"
        print(colors.fg.cyan + msg + colors.reset)
    return buff

def remove_random_space(buff):
    
    
    ptn = b' {3,}'

    _, match_count = log_ptn_info(buff, ptn)

    if match_count > 0:
        
        msg = "[+] TASK: REMOVING SPACE"
        print(colors.fg.cyan + msg + colors.reset)
        
        buff = removed_matched_ptn(buff, ptn)

    return buff

def remove_random_semicolon(buff):
    

    ptn = b"(?m)(;@;|;|;;)"

    _, match_count = log_ptn_info(buff, ptn)

    if match_count > 0:
        msg = f"[+] TASK: REMOVING RANDOM SEMICOLON"
        print(colors.fg.cyan + msg + colors.reset)

        buff = removed_matched_ptn(buff, ptn)


    return buff

def remove_random_at(buff):

    ptn = b"(?m)(@@)"

    _, match_count = log_ptn_info(buff, ptn)

    if match_count > 0:
        msg = f"[+] TASK: REMOVING RANDOM @"
        print(colors.fg.cyan + msg + colors.reset)
        
        buff = removed_matched_ptn(buff, ptn, )
        
    return buff


def remove_random_newline(buff):

    ptn = b"\n{2,}"

    _, match_count = log_ptn_info(buff, ptn, )

    if match_count > 0:
        msg = f"[+] TASK: REMOVING RANDOM NEWLINE"
        print(colors.fg.cyan + msg + colors.reset)
        
        buff = removed_matched_ptn(buff, ptn, b"\n")
    return buff


def remove_easy_anti_detect(buff):

    ptn = b"\^"

    _, match_count = log_ptn_info(buff, ptn)

    if match_count > 0:
        msg = f"[+] TASK: REMOVING EASY ANTI DETECT"
        print(colors.fg.cyan + msg + colors.reset)
        
        buff = removed_matched_ptn(buff, ptn)

    return buff


def remove_anti_detect(buff):

    ### find the mark of ofuscator: %obfuscator_str%
    ptn = b'%([^\%]*)%'

    matches, match_count = log_ptn_info(buff, ptn)

    start_pos = 0

    ### enumerate match regex one by one to avoid alignment problem
    while True:
        
        ### find the first match
        match = re.search(ptn, buff[start_pos:])
        if not match:
            break
        else:
            ### find the match boundaries
            s, e = match.span()

            ### aligned the start and end boundaries in each iteration
            s = s + start_pos
            e = e + start_pos

            ### find the obfuscated index. these 2 are the same but different approach
            ### this is just to check which is better. 
            obf_text = match.group(1)
            _obf_text = buff[s:e]
            
            ### minumum length of match boundries must be > 2
            if e - s > 2:
                if contains_obfuscator(_obf_text):
                    buff = buff[:s] + buff[e:]
                else:
                    start_pos = e - 1
            else:
                start_pos = e -1 
    
    msg = f"[+] TASK: REMOVING ANTI DETECT"
    print(colors.fg.cyan + msg + colors.reset)
    return buff

def recover_public_enc_key_str(buff):

    ptn = b"%public:~(.+?),1%"

    start_pos = 0
    while True:

        ### find the first match
        match = re.search(ptn[start_pos:], buff, re.IGNORECASE)

        if not match:
            
            break
        else:
            ### find the match boundaries
            s, e = match.span()

            ### find the matched string
            raw_match = match.group(0)
            indx = match.group(1)
            
            ### decode the regex match
            replacement_char = ALPHABET[int(indx,10)].encode('utf-8')
            buff = buff[:s] + replacement_char + buff[e:]

            


    msg = f"[+] TASK: RECOVER PUBLIC KEY"
    print(colors.fg.cyan + msg + colors.reset)

    return buff


def recover_other_enc_key_str(buff):

    ### patter nfor possible generated encoding key string
    ptn =status.decoder_ptn
    
    ###key dictionary
    encoding_keys = {}
    
    start_pos = 0
    while True:

        ### find the possible first match
        match = re.search(ptn, buff[start_pos:], re.IGNORECASE)
        
        if not match:
            
            break
        else:
            ### find the match boundaries
            s, e = match.span()

            ### aligned the start and end boundaries in each iteration
            s = s + start_pos
            e = e + start_pos
            

            ### collect the encoding key name and encoding key value
            enc_key_name = match.group(1)
            enc_val_name = match.group(2)
            
            ### save the key strings
            if enc_key_name not in encoding_keys:
                encoding_keys[enc_key_name] = enc_val_name
        
                buff = decode_key_str(buff, encoding_keys)
                start_pos = 0
            else:
                start_pos = e - 1 

                
    ### show all found decoding keys
    k_ctr =1

    for k, v in encoding_keys.items():
        msg = f"[+] TASK: RECOVER KEY: {v}"
        print(colors.fg.cyan + msg + colors.reset)
        k_ctr+=1

    return buff, encoding_keys

def remove_random_if(buff):
    
    ptn = b"@?if exist %.+?%|@?if [0-9]{1,} LsS [0-9]{2,}|@?if [0-9]{1,} EQU [0-9]{1,}|@?For \/l %%y iN (.+?) dO|@?if [0-9]{1,} EQU 0 \(@exit\) else|\(@exit\)"
    

    _, match_count = log_ptn_info(buff, ptn)

    if match_count > 0:
        msg = f"[+] TASK: REMOVING RANDOM IF"
        print(colors.fg.cyan + msg + colors.reset)

        buff = removed_matched_ptn(buff, ptn)

    return buff

def deobfuscation_process(buff, file_path):
    process_file = f"[+] TASK: processing: {file_path} ..."
    print(colors.fg.cyan + process_file + colors.reset)
    ###############################################################################################
    #status.bom                       = False
    #status.random_at                 = False
    #status.random_semicolon          = False
    #status.random_space              = False #possible crashes
    #status.random_if                 = False
    #status.code_obfuscation          = False
    #status.random_newline            = False #possible crashes
    #status.easy_anti_detect          = False
    #status.anti_detect               = False
    #status.public_enc_key_str        = False
    #status.other_enc_key_str         = False
    ###############################################################################################
    
    ### removed 4 bytes UTF-16 Byte ORder Mark (BOM)
    if status.bom == True:
        buff = remove_bom(buff)

    ### try to remove series of space
    if status.random_space == True:
        buff = remove_random_space(buff)

    ### try to remove random_semicolon
    if status.random_semicolon == True:
        buff = remove_random_semicolon(buff)

    ### try to remove random_at
    if status.random_at == True:
        buff = remove_random_at(buff)

    ### try to remove random_newline
    if status.random_newline == True:
        buff = remove_random_newline(buff)

    ### try to remove easy_anti_detect
    if status.easy_anti_detect == True:
        buff = remove_easy_anti_detect(buff)

    ### try to remove anti_detect
    if status.anti_detect == True:
        buff = remove_anti_detect(buff)

    ### try to recover the public encoding key string
    if status.public_enc_key_str == True:
        buff = recover_public_enc_key_str(buff)

    ### try to recover the other encoding key string (default count 4)
    if status.other_enc_key_str == True:
        buff, enc_keys = recover_other_enc_key_str(buff)

    ### try to remove random_if
    if status.random_if == True:
        buff = remove_random_if(buff)

    ### create output folder
    output_path = os.path.join(os.getcwd(), DEOBFUS_DIR)
    if not os.path.isdir(output_path):
        os.mkdir(output_path)

    ### get the base file name
    base_name = os.path.basename(file_path)
    out_file_name = os.path.join(output_path, "debobus-" + base_name)
    print(colors.fg.lightgreen + f"[+] TASK: DE-OBFUSCATED FILE PATH: {out_file_name}" + colors.reset)
    print(colors.fg.lightgreen + "[+] TASK: FINAL OUTPUT - POSSIBLE DEOBFUSCATION" + colors.reset)


    print(colors.fg.lightgreen + "█" * 0x70 + colors.reset)
    print(colors.fg.lightgreen + repr(buff.decode('utf-8')) + colors.reset)
    print(colors.fg.lightgreen + "█" * 0x70 + colors.reset)

    with open(out_file_name, "wb") as fw:
        fw.write(buff)
    return



def banner():

    banner = '''
    
    ██████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██║   ██║██╔════╝
    ██║  ██║██████╔╝██║   ██║██████╔╝██║   ██║███████╗
    ██║  ██║██╔══██╗██║   ██║██╔══██╗██║   ██║╚════██║
    ██████╔╝██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████║
    ╚═════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
                                                    
    [ DE-OBFUSCATE 'ABOBUS'       ]
    [ by. Br3akp0int @tccontre18  ]
    '''
    print(colors.fg.cyan + banner + colors.reset)
    print(colors.fg.cyan + "█" * 0x70 + colors.reset)
    print("\n")
    return

def main():

    ### Call the function to enable virtual terminal processing
    enable_virtual_terminal_processing()

    ### clear screen
    clear_screen()

    ### show banner
    banner()

    ### grab some input
    parser = argparse.ArgumentParser(description = "Abobus-Deobfuscator")
    parser.add_argument('-i', '-bat-file',  dest ='batfile', help = "abobus obfuscated .bat files. Either file path or dir path for multiple .bat files", required=True)
    args = parser.parse_args()

    if os.path.isfile(args.batfile):
        file_path = args.batfile
        with open(file_path, "rb") as fr:
            buff = fr.read()
        deobfuscation_process(buff, args.batfile)
    elif os.path.isdir(args.batfile):
        enumerate_files(args.batfile)




if __name__ == "__main__":
    main()
