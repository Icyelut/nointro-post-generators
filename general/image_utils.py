import os
import subprocess
import re

def clear_tif_documentname(directory):
    if os.path.isdir(directory):
        subprocess.run(["exiftool", "-ext", "tif", "-overwrite_original", "-DocumentName=",  directory], check=True)


def run(parsed_args):
    if parsed_args.folder:
        working_directory = parsed_args.folder
    else:
        working_directory = os.getcwd()

    clear_tif_documentname(working_directory)