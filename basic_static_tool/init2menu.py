import magic
import zipfile
import urllib.parse
import re
from PyPDF2 import PdfReader
import rarfile
import pdfplumber
import py7zr
from alive_progress import alive_bar
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from rich import print as rprint
from rich.table import Table
def print_greeting():
    print('''
                                                         .x+=:.        s                     s       .          ..      
                                                        z`    ^%      :8                    :8      @88>  < .z@8"`      
               x.    .                    x.    .          .   <k    .88                   .88      %8P    !@88E        
     uL      .@88k  z88u        uL      .@88k  z88u      .@8Ned8"   :888ooo       u       :888ooo    .     '888E   u    
 .ue888Nc.. ~"8888 ^8888    .ue888Nc.. ~"8888 ^8888    .@^%8888"  -*8888888    us888u.  -*8888888  .@88u    888E u@8NL  
d88E`"888E`   8888  888R   d88E`"888E`   8888  888R   x88:  `)8b.   8888    .@88 "8888"   8888    ''888E`   888E`"88*"  
888E  888E    8888  888R   888E  888E    8888  888R   8888N=*8888   8888    9888  9888    8888      888E    888E .dN.   
888E  888E    8888  888R   888E  888E    8888  888R    %8"    R88   8888    9888  9888    8888      888E    888E~8888   
888E  888E    8888 ,888B . 888E  888E    8888 ,888B .   @8Wou 9%   .8888Lu= 9888  9888   .8888Lu=   888E    888E '888&  
888& .888E   "8888Y 8888"  888& .888E   "8888Y 8888"  .888888P`    ^%888*   9888  9888   ^%888*     888&    888E  9888. 
*888" 888&    `Y"   'YP    *888" 888&    `Y"   'YP    `   ^"F        'Y"    "888*""888"    'Y"      R888" '"888*" 4888" 
 `"   "888E                 `"   "888E                                       ^Y"   ^Y'               ""      ""    ""   
.dWi   `88E                .dWi   `88E                                                                                  
4888~  J8%                 4888~  J8%                                                                                   
 ^"===*"`                   ^"===*"`                                                                                   
    ''')

def extract_info_from_pdf(file_path):
    with pdfplumber.open(file_path) as pdf:
        text = '\n'.join(page.extract_text() for page in pdf.pages)

        # Write the extracted text to a .txt file
        with open('extracted_text.txt', 'w') as f:
            f.write(text)

    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    domains = [urllib.parse.urlparse(url).netloc for url in urls]

    return urls, ips, domains

def identify_file_type(file_path):
    mime = magic.Magic(mime=True)
    return mime.from_file(file_path)

def is_password_protected(file_path, file_type):
    if "zip" in file_type:
        try:
            with zipfile.ZipFile(file_path) as zf:
                badfile = zf.testzip()
                if badfile:
                    return True
        except RuntimeError:
            return True
    elif "rar" in file_type:
        try:
            with rarfile.RarFile(file_path) as rf:
                rf.testrar()
        except rarfile.RarCannotExec:
            return True
    elif "7z" in file_type:
        try:
            with py7zr.SevenZipFile(file_path, mode='r') as z:
                z.test()
        except py7zr.exceptions.Bad7zFile:
            return True
    elif "pdf" in file_type:
        try:
            with pdfplumber.open(file_path) as pdf:
                text = '\n'.join(page.extract_text() for page in pdf.pages)
            return False
        except:
            return True

def main_menu():
    while True:
        print("\n[1]: Select & Analyze a file")
        print("[2]: Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            filename = askopenfilename()
            analyze_file(filename)
        elif choice == '2':
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")

def analyze_file(filename):
    with alive_bar(4, title='Analyzing...') as bar:
        file_type = identify_file_type(filename)
        bar()
        is_protected = is_password_protected(filename, file_type)
        bar()

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("File Path")
        table.add_column("File Type")
        table.add_column("Password Protected")

        row_data = [filename, file_type, "Yes" if is_protected else "No"]

        if "pdf" in file_type and not is_protected:
            urls, ips, domains = extract_info_from_pdf(filename)
            table.add_column("URLs")
            table.add_column("IP Addresses")
            table.add_column("Domain Names")
            row_data.extend([", ".join(urls), ", ".join(ips), ", ".join(domains)])
        bar()

        table.add_row(*row_data)
        bar()

    rprint(table)

print_greeting()
main_menu()