import codecs
import os
import pathlib
from shutil import copyfile
import re
import subprocess
import tempfile
from general.hash_utils import hash_file, hash_directory_recursive
from general.image_utils import clear_tif_documentname
from datetime import date


no_intro_post_template = """[OPTIONAL] DoM URL GOES HERE

Dump Tool: nxdumptool rewrite branch commit f6d133d (XCI + Initial Area)
Dump Date: {}

[code]
Game title: [REQUIRED]
Game title (native): {} [CHECK THIS]
Region: Japan [CHECK THIS]
Languages: Japanese [CHECK THIS]
Cart Serial: [REQUIRED]
Cart Reverse Serial: [REQUIRED]
Cart Revision (If applicable): [REQUIRED]
Box Barcode: {}
Box Serial: {}
Size: {}


{}

[/code]
"""

def find_file_matching(directory, regex_str):
    search_re = re.compile(regex_str, re.IGNORECASE)

    matching_file_path = None
    all_files_list = os.listdir(directory)
    for file in all_files_list:
        if search_re.search(file):
            matching_file_path = pathlib.Path(file).resolve(strict=False).expanduser()
            break

    return matching_file_path

def create_initial_area_file(directory):
    key_area_file = find_file_matching(directory, r"\(Key Area\).*\.bin$")

    if not key_area_file:
        return False

    with open( os.path.join(directory, key_area_file), "rb") as f:
        data = f.read(512)

    with open(os.path.join(directory, "Initial Area.bin"), "wb") as outfile:
        outfile.write(data)
        print("Created Initial Area.bin from {}".format(key_area_file))
        return True

    return False

def generate(parsed_args):
    xci_file_re = re.compile(r"\.xci$", re.IGNORECASE)


    xci_file = None
    if parsed_args.xci_file:
        working_directory = os.path.split(parsed_args.xci_file)[0]
        xci_file = pathlib.Path(parsed_args.xci_file).resolve(strict=False).expanduser()
    else:
        working_directory = os.getcwd()
        all_files_list = os.listdir(working_directory)
        for file in all_files_list:
            if xci_file_re.search(file):
                xci_file = pathlib.Path(file).resolve(strict=False).expanduser()
                break

    if xci_file is None:
        print(f"[ERROR] xci file not found in directory {working_directory}")
        raise FileNotFoundError

    size = os.path.getsize(xci_file)

    xci_name_re = re.compile(r" \[[0-9A-Z]+\].*\.xci", re.IGNORECASE)
    native_title = xci_name_re.sub("", xci_file.name)

    initial_data_file = find_file_matching(working_directory, r"\(Initial Data\).*\.bin$")
    if initial_data_file is None:
        success = create_initial_area_file(working_directory)
    else:
        success = True

    if not success:
        print("[WARNING] Could not find key area / Initial Data file!")

    output_template = """File: {}
        Size:     {}
        CRC32:    {}
        MD5:      {}
        SHA1:     {}
        SHA256:   {}
        SHA512:   {}
        SHA3-512: {}
    """

    print("Hashing files...")
    file_info_list = []
    hash_included_files_list = [r"\.xci$", r"Initial Area\.bin", r"\(Initial Data\).*\.bin$"]
    hash_list = hash_directory_recursive(working_directory, root_str="", include_re=hash_included_files_list)
    for item in hash_list:
        file_info_list.append(output_template.format(*item))

    file_info_output = "\n\n".join(file_info_list)

    if parsed_args.no_box:
        box_barcode = "(Don't have the box)"
        box_serial = "(Don't have the box)"
    else:
        box_barcode = "[OPTIONAL]"
        box_serial = "[OPTIONAL]"

    today = date.today()

    if parsed_args.outfile:
        outfile = parsed_args.outfile
    else:
        outfile = os.path.join(working_directory, "no_intro_post.txt")

    with codecs.open(outfile, "w", "utf8") as outf:
        outf.write(no_intro_post_template.format(today, native_title, box_barcode, box_serial, size, file_info_output))

    clear_tif_documentname(os.path.join(working_directory, "RAW"))
    clear_tif_documentname(working_directory)
