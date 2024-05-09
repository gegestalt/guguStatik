import magic
import zipfile
import urllib.parse
import pandas as pd 
from docx import Document
from langdetect import detect
from oletools.olevba import VBA_Parser
import pefile
import math
import datetime
import re
import requests
import string
from collections import Counter
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
import os

file_types = {
    ".exe": "Executable file",
    ".pdf": "Portable Document Format",
    ".doc": "Microsoft Word document (pre-2007)",
    ".docx": "Microsoft Word document",
    ".xls": "Microsoft Excel spreadsheet (pre-2007)",
    ".xlsx": "Microsoft Excel spreadsheet",
    ".ppt": "Microsoft PowerPoint presentation (pre-2007)",
    ".pptx": "Microsoft PowerPoint presentation",
    ".zip": "Compressed file archive",
    ".rar": "RAR archive",
    ".7z": "7-Zip archive",
    ".js": "JavaScript file",
    ".vbs": "VBScript file",
    ".scr": "Screen saver executable",
    ".lnk": "Windows shortcut file",
    ".bat": "Batch file",
    ".html": "HTML file",
    ".php": "PHP file",
    ".swf": "Small Web Format (used for animations)",
    ".gif": "Graphics Interchange Format file",
    ".png": "Portable Network Graphics file",
    ".jpg": "JPEG image file",
    ".jpeg": "JPEG image file",
    ".bmp": "Bitmap image file",
    ".svg": "Scalable Vector Graphics file",
    ".ps1": "PowerShell script",
    ".chm": "Compiled HTML Help file",
    ".xml": "eXtensible Markup Language file",
    ".rtf": "Rich Text Format file",
    ".mhtml": "MIME HTML archive file",
    ".iso": "ISO disc image",
    ".tar": "Tarball archive file",
    ".gz": "Gzip compressed file",
    ".bz2": "Bzip2 archive file",
    ".dll": "Dynamic Link Library",
    ".tmp": "Temporary file",
    ".msp": "Microsoft Patch file",
    ".msi": "Microsoft Installer package",
    ".reg": "Registry file",
    ".hkcu": "HKCU Registry file",
    ".eml": "Email message file",
    ".db": "Database file",
    ".sql": "SQL database file",
    ".apk": "Android Package file",
    ".app": "MacOS application",
    ".vb": "Visual Basic script",
    ".jar": "Java ARchive",
    ".java": "Java source file",
    ".class": "Java class file",
    ".sh": "Unix shell script",
    ".py": "Python script",
    ".rb": "Ruby script",
    ".ps": "PostScript file",
    ".eps": "Encapsulated PostScript file",
    ".mp3": "MP3 audio file",
    ".wav": "Waveform Audio File Format",
    ".mp4": "MPEG-4 video file",
    ".avi": "Audio Video Interleave file",
    ".mov": "QuickTime Movie file",
    ".xlsm": "Macro-enabled Excel workbook",
    ".pub": "Microsoft Publisher document",
    ".sct": "Windows Script Component",
    ".wsf": "Windows Script File",
    ".wsh": "Windows Script Host Settings file",
    ".ppsx": "PowerPoint Slide Show"
}

def identify_file_type(file_path):
    _, extension = os.path.splitext(file_path)
    return file_types.get(extension.lower(), "Unknown file type")
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



def has_macros(filename):
    vbaparser = VBA_Parser(filename)
    return vbaparser.detect_vba_macros()

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
    

    elif "pdf" or "Portable Document Format" in file_type:
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
        print("[3]: Analyze a PE or DLL")
        choice = input("Enter your choice: ")

        if choice == '1':
            filename = askopenfilename()
            analyze_file(filename)
        elif choice == '2':
            break
        elif choice == '3':
            filename = askopenfilename()
            pe_info = extract_info_from_pe(filename)

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("File Path")
            table.add_column("URLs")
            table.add_column("Domains")
            table.add_column("IP Addresses")
            table.add_column("Architecture")
            table.add_column("General Entropy")
            table.add_column("File Size")
            table.add_column("Number of Sections")
            table.add_column("Compilation Date")
            table.add_column("DLLs")
            table.add_column("Packed")
            table.add_column("Packing Algorithm")
            for i, section_info in enumerate(pe_info['sections_info'], start=1):
                section_table = Table(show_header=True, header_style="bold magenta")
                section_table.add_column("Section Name")
                section_table.add_column("Entropy")
                section_table.add_column("Virtual Size")
                section_table.add_column("Raw Size")
            
                row_data_section = [section_info['Name'], str(section_info['Entropy']), str(section_info['Virtual Size']), str(section_info['Raw Size'])]
                section_table.add_row(*row_data_section)
                rprint(section_table)

            row_data = [
                filename, 
                ", ".join(s.decode() for s in pe_info['urls']),  
                ", ".join(s.decode() for s in pe_info['domains']),  
                ", ".join(s.decode() for s in pe_info['ips']),  
                pe_info['architecture'], 
                str(pe_info['general_entropy']), 
                str(pe_info['file_size']), 
                str(pe_info['num_sections']), 
                str(pe_info['compilation_date']), 
                ", ".join(s.decode() for s in pe_info['dlls']),  
                str(pe_info['packed']), 
                pe_info['packing_algorithm']
            ]

            table.add_row(*row_data)
            rprint(table)
        else:
            print("Invalid choice. Please enter 1, 2 or 3.")
                       

def entropy(data):
    if not data:
        return 0.0
    occurences = Counter(bytearray(data))
    entropy = 0
    len_data = len(data)
    for x in occurences.values():
        p_x = float(x) / len_data
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def get_tlds():
    tlds = requests.get('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
    return tlds.text.split('\n')[1:-1]

def analyze_sections(pe):
    sections_info = []
    for section in pe.sections:
       
        section_info = {
            "Name": section.Name.decode(errors='ignore'),
            "Entropy": entropy(section.get_data()),
            "Virtual Size": section.Misc_VirtualSize,
            "Raw Size": len(section.get_data())
        }
        
        sections_info.append(section_info)
    return sections_info

def extract_info_from_pe(filename):
    pe = pefile.PE(filename)

    # 3.1
    tlds = get_tlds()
    with open(filename, 'rb') as f:
        data = f.read()
    strings = re.findall(b'[A-Za-z0-9/\-:]{4,}', data)
    urls = [s for s in strings if b'http' in s]
    domains = [s for s in strings if any(tld.encode() in s for tld in tlds)]
    ips = [s for s in strings if re.match(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)]

    # 3.2
    architecture = 'x86' if pe.FILE_HEADER.Machine == 0x014c else 'x86-x64' if pe.FILE_HEADER.Machine == 0x8664 else 'Unknown'
    general_entropy = entropy(data)
    file_size = len(data)
    num_sections = len(pe.sections)
    sections = [(s.Name, entropy(s.get_data()), s.Misc_VirtualSize, len(s.get_data())) for s in pe.sections]
    compilation_date = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
    dlls = [entry.dll for entry in pe.DIRECTORY_ENTRY_IMPORT]

    # 3.3
    packed = any(s.get_entropy() > 7 for s in pe.sections)
    packing_algorithm = 'Unknown'
    sections_info = analyze_sections(pe)
    return {
        'urls': urls,
        'domains': domains,
        'ips': ips,
        'architecture': architecture,
        'general_entropy': general_entropy,
        'file_size': file_size,
        'num_sections': num_sections,
        'sections': sections,
        'compilation_date': compilation_date,
        'dlls': dlls,
        'packed': packed,
        'packing_algorithm': packing_algorithm,
        'sections_info': sections_info,
    }
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
            pdf_page_count = len(PdfReader(filename).pages)
            pdf_page_count= math.ceil(pdf_page_count)
            table.add_column("URLs")
            table.add_column("IP Addresses")
            table.add_column("Domain Names")
            table.add_column("Page Count")
            row_data.extend([", ".join(urls), ", ".join(ips), ", ".join(domains), (str(pdf_page_count))])
        elif "doc" in file_type and not is_protected:
            doc = Document(filename)
            text = ' '.join(paragraph.text for paragraph in doc.paragraphs)
            language = detect(text)
            num_pages = len(doc.paragraphs)  
            contains_macros = has_macros(filename)  

            table.add_column("Language")
            table.add_column("Number of Pages")
            table.add_column("Contains Macros")
            row_data.extend([language, str(num_pages), "Yes" if contains_macros else "No"])  
        bar()

        table.add_row(*row_data)
        bar()

    rprint(table)

print_greeting()
main_menu()