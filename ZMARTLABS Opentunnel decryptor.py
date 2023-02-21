#base :| Copyright (c) ::ZMART services:: Official telegram page by @ZMARTGH,
#!/usr/bin/env python3
import re,os,time,zlib,base64
from time import sleep
from shutil import which
from sys import stdin, stdout, stderr
from argparse import ArgumentParser
from pathlib import Path
from base64 import b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

DEFAULT_FILE_EXTENSION = '.tmt'

# pass
PASSWORDS = { 
    '.tnl': b'B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg',  #✓
}

def error(error_msg = 'Corrupted/unsupported file.'):
    stderr.write(f'\033[41m\033[30m X \033[0m {error_msg}\n')
    stderr.flush()

    exit(1)

def warn(warn_msg):
    stderr.write(f'\033[43m\033[30m ! \033[0m {warn_msg}\n')
    stderr.flush()

def ask(prompt):
    stderr.write(f'\033[104m\033[30m ? \033[0m {prompt} ')
    stderr.flush()

    return input()

def human_bool_to_bool(human_bool):
    return 'y' in human_bool

def main():
    
    parser = ArgumentParser()
    parser.add_argument('file', help='file to decrypt')

    output_args = parser.add_mutually_exclusive_group()
    output_args.add_argument('--output', '-o', help='file to output to')
    output_args.add_argument('--stdout', '-O', action='store_true', help='output to stdout', default=True)

    args = parser.parse_args()

    encrypted_contents = open(args.file, 'r').read()

    # determine the file's extension
    file_ext = Path(args.file).suffix
    
    if file_ext not in PASSWORDS:
        warn(f'Unknown file extension, defaulting to {DEFAULT_FILE_EXTENSION}')
        file_ext = DEFAULT_FILE_EXTENSION

    # split the file
    split_base64_contents = encrypted_contents.split('.')


    split_contents = list(map(b64decode, split_base64_contents))

    decryption_key = PBKDF2(PASSWORDS[file_ext], split_contents[0], hmac_hash_module=SHA256)

    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=split_contents[1])
    decrypted_contents = cipher.decrypt_and_verify(split_contents[2][:-16], split_contents[2][-16:])

    if args.output:
        output_file_path = Path(args.output)

        
        if output_file_path.exists() and output_file_path.is_file():
            
            if not human_bool_to_bool(ask(f'A file named "{args.output}" already exists. Overwrite it? (y/n)')):
                
                exit(0)
        
        
        output_file = open(output_file_path, 'wb')
        output_file.write(decrypted_contents)
    elif args.stdout:
        
        config = decrypted_contents.decode('utf-8','ignore')
        
        message = " 𝐃𝐞𝐜𝐫𝐲𝐩𝐭 𝐒𝐮𝐜𝐜𝐞𝐬𝐬ful!\n"
        message +=" ZMARTLABS✓\n"  
        message +=" FixedBy: @ZMARTGH\n"     
        message +=" [Telegram: https://t.me/zmart\n"
        message += " =====[ ZMARTLABS 𝗗𝗘𝗖𝗥𝗬𝗣𝗧𝗢𝗥 ]======>\n"
        sshadd ='';port ='';user='';passw=''
        configdict ={}
        for line in config.split('\n'):
        	if line.startswith('<entry'):
        		line = line.replace('<entry key="','')
        		line = line.replace('</entry','')
        		line = line.split('">')
        		if len(line) >1:
        			configdict[line[0]] = line[1].strip(">")
        			
        		else:
        			configdict[line[0].strip('"/>')]= " ***"
        			#print(f'[>] {line} ==> X')
        for k,v in configdict.items():
        	if k in ["sshServer","sshPass","sshUser","sshPort"]:
        		continue
        	else:
        		message += f'〔⎆〕{k} » {v}\n'
        message += f'〔⎆〕sshAddress » {configdict["sshServer"]}:{configdict["sshPort"]}@{configdict["sshUser"]}:{configdict["sshPass"]}\n'     	
        message += " =====[ ZMARTLABS 𝗗𝗘𝗖𝗥𝗬𝗣𝗧𝗢𝗥 ]======>"
        # write it to stdout
        out = open('C:\Windows\System32\cmd.exe\ZML_TNL.txt', 'w')
        out.write(message)
        out.close()
        print(message)
        os.system("cat C:\Windows\System32\cmd.exe\ZML_TNL.txt")
        print('♮ 𝐑𝐞𝐬𝐮𝐥𝐭 𝐂𝐨𝐩𝐢𝐞𝐝 𝐓𝐨 𝐂𝐥𝐢𝐩𝐛𝐨𝐚𝐫𝐝\n♮ 𝐇𝐚𝐯𝐞 𝐚 𝐆𝐫𝐞𝐚𝐭 𝐃𝐚𝐲.\n\n')

if __name__ == '__main__':
    try:
        main()
    except Exception as err:
        error(err)
