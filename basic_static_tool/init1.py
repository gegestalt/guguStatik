from rich import print
from rich.table import Table

import magic
import zipfile
import rarfile
import py7zr

from tkinter import Tk
from tkinter.filedialog import askopenfilename
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
    else:
        return False

Tk().withdraw()
filename = askopenfilename()

file_type = identify_file_type(filename)
is_protected = is_password_protected(filename, file_type)

table = Table(show_header=True, header_style="bold magenta") #Since I am dealing with Runtime errors I used the rich library to make the output more readable.
table.add_column("File Path")
table.add_column("File Type")
table.add_column("Password Protected")

table.add_row(filename, file_type, "Yes" if is_protected else "No")


print(table)