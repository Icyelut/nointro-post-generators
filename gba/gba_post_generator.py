import codecs
import os
import pathlib
from shutil import copyfile
import re
import subprocess
import tempfile
from general.hash_utils import hash_file
from general.image_utils import clear_tif_documentname

ndecrypt_path = "C:\\MyPrograms\\Utilities\\3DS\\NDecrypt\\NDecrypt.exe"

no_intro_post_template = """Dumped with GodMode {} on an N3DS.
[OPTIONAL] DoM URL GOES HERE

Additional encrypted hashes were created with NDecrypt v0.2.2

[code]
Encrypted CRC32:    {}
Encrypted MD5:      {}
Encrypted SHA1:     {}
Encrypted SHA256:   {}
Encrypted SHA512:   {}
Encrypted SHA3-512: {}
Game title: REQUIRED
Game title (native): OPTIONAL
ROM Region: {}
ROM Revision: {}
ROM Serial: {}
Languages/Language Select: REQUIRED

CRC32:    {}
MD5:      {}
SHA1:     {}
SHA256:   {}
SHA512:   {}
SHA3-512: {}

Size:     {}
Cart Serial: REQUIRED
Additional Cart Serial: REQUIRED
Box Barcode: {}
Box Serials: {}
PCB serial(s): ▼ •
Chip(s) serial(s) (optional): 
Cart ID: {}
[/code]


GodMode9 cart info txt:
[code]
{}
[/code]


GameHeader output:
[code]
{}
[/code]
"""


def clear_exif(full_file_path):
    subprocess.run(["exiftool", "-overwrite_original", "-exif:all=", "-JFIF:all=", full_file_path], check=True)

    working_directory = os.path.split(full_file_path)[0]
    tmp_file_re = re.compile(r".*_exiftool_tmp", re.IGNORECASE)
    all_files_list = os.listdir(working_directory)
    for file in all_files_list:
        if tmp_file_re.search(file):
            tmp_file = pathlib.Path(file).resolve(strict=False).expanduser()
            os.remove(tmp_file)


def clear_tif_documentname(directory):
    subprocess.run(["exiftool", "-overwrite_original", "-DocumentName=", "-ext tif", directory], check=True)


def get_encrypted_hashes(nds_file_path):
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir_file = os.path.join(tmpdirname, os.path.split(nds_file_path)[1])
        copyfile(nds_file_path, tmpdir_file)

        cmd = [ndecrypt_path, "e", tmpdir_file]
        subprocess.run(cmd, check=True)

        return hash_file(tmpdir_file)


def check_hashes(calc_hash_iter, read_hash_iter, hash_type_str):
    all_match = True

    for hash1, hash2 in zip(calc_hash_iter, read_hash_iter):
        if hash1 != hash2:
            all_match = False
            break

    if not all_match:
        raise ValueError("{} hashes didn't match. Calculated hashes: {}, read hashes: {}".format(hash_type_str,
                                                                                                 calc_hash_iter,
                                                                                                 read_hash_iter))
    return True

def parse_gm9_txt(gm9_txt_path):
    cart_id_re = re.compile(r"Cart ID +: +([A-Z0-9]+)")
    gm9_ver_re = re.compile(r"GM9 Version +: +([\.a-zA-Z0-9]+)")
    gm9_txt_lines_list = []
    with open(gm9_txt_path, "r", encoding="utf8") as infile:
        for current_line in infile:
            gm9_txt_lines_list.append(current_line)
            m = cart_id_re.match(current_line)
            if m:
                cart_id = m.group(1)

            m = gm9_ver_re.match(current_line)
            if m:
                gm9_version = m.group(1)

    return cart_id, gm9_version, gm9_txt_lines_list

def generate(parsed_args):
    path_string_censor = "Path:               [EXPUNGED]"
    path_string_re = re.compile(r"Path: {15}")
    nds_file_re = re.compile(r"\.nds$", re.IGNORECASE)

    nds_file = None
    if parsed_args.nds_file:
        working_directory = os.path.split(parsed_args.nds_file)[0]
        nds_file = pathlib.Path(parsed_args.nds_file).resolve(strict=False).expanduser()
    else:
        working_directory = os.getcwd()
        all_files_list = os.listdir(working_directory)
        for file in all_files_list:
            if nds_file_re.search(file):
                nds_file = pathlib.Path(file).resolve(strict=False).expanduser()
                break

    if nds_file is None:
        print(f"[ERROR] nds file not found in directory {working_directory}")
        raise FileNotFoundError

    nds_name = nds_file_re.sub("", nds_file.name)

    all_files_list = os.listdir(working_directory)
    nds_enc_file_re = re.compile(r"\.nds\.enc$", re.IGNORECASE)
    for file in all_files_list:
        if nds_enc_file_re.search(file):
            nds_enc_file = pathlib.Path(file).resolve(strict=False).expanduser()
            break

    if nds_enc_file is None:
        print(f"[WARNING] nds.enc file not found in directory {working_directory}")
    else:
        print("[INFO] Found Godmode9 encrypted NDS '{}'".format(nds_enc_file))


    if parsed_args.gameheader_txt:
        gameheader_txt = parsed_args.gameheader_txt
    else:
        gameheader_txt = os.path.join(working_directory, "gameheader.txt")

    all_files_list = os.listdir(working_directory)
    gameheader_lines_list = []

    with open(gameheader_txt, "r", encoding="utf_16") as infile:
        for current_line in infile:
            current_line = current_line.rstrip("\r\n")
            if path_string_re.match(current_line):
                gameheader_lines_list.append(path_string_censor)
            else:
                gameheader_lines_list.append(current_line)


    length = -1
    decrypted_crc32 = ""
    decrypted_md5 = ""
    decrypted_sha1 = ""
    serial = ""
    region = ""
    revision = ""
    encrypted_crc32 = ""
    encrypted_md5 = ""
    encrypted_sha1 = ""

    length_re = re.compile("Length: {13}([0-9]+)")
    decrypted_crc32_re = re.compile(r"CRC32: {14}([A-Z0-9]+)")
    decrypted_md5_re = re.compile(r"MD5: {16}([A-Z0-9]+)")
    decrypted_sha1_re = re.compile(r"SHA1: {15}([A-Z0-9]+)")
    serial_region_re = re.compile(r"Game Serial: {8}([A-Z0-9]+) \(([a-zA-Z]+)\)")
    revision_re = re.compile("Version: {12}(.+)")
    encrypted_crc32_re = re.compile(r"Encrypted CRC32: {4}([A-Z0-9]+)")
    encrypted_md5_re = re.compile(r"Encrypted MD5: {6}([A-Z0-9]+)")
    encrypted_sha1_re = re.compile(r"Encrypted SHA1: {5}([A-Z0-9]+)")

    for line in gameheader_lines_list:
        m = length_re.match(line)
        if m:
            length = m.group(1)

        m = decrypted_crc32_re.match(line)
        if m:
            decrypted_crc32 = m.group(1)

        m = decrypted_md5_re.match(line)
        if m:
            decrypted_md5 = m.group(1)

        m = decrypted_sha1_re.match(line)
        if m:
            decrypted_sha1 = m.group(1)

        m = serial_region_re.match(line)
        if m:
            serial = m.group(1)
            region = m.group(2)

        m = revision_re.match(line)
        if m:
            revision = m.group(1)

        m = encrypted_crc32_re.match(line)
        if m:
            encrypted_crc32 = m.group(1)

        m = encrypted_md5_re.match(line)
        if m:
            encrypted_md5 = m.group(1)

        m = encrypted_sha1_re.match(line)
        if m:
            encrypted_sha1 = m.group(1)

    calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1, calculated_dec_sha256, calculated_dec_sha512, \
        calculated_dec_sha3_512 = hash_file(nds_file)
    calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1, calculated_enc_sha256, calculated_enc_sha512, \
        calculated_enc_sha3_512 = get_encrypted_hashes(nds_file)

    check_hashes((calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1), (decrypted_crc32, decrypted_md5,
                                                                                   decrypted_sha1), "Decrypted")
    check_hashes((calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1), (encrypted_crc32, encrypted_md5,
                                                                                   encrypted_sha1), "Encrypted")

    if nds_enc_file is not None:

        godmode9_enc_crc32, godmode9_enc_md5, godmode9_enc_sha1, godmode9_enc_sha256, godmode9_enc_sha512, \
        godmode9_enc_sha3_512 = hash_file(nds_enc_file)
        try:
            check_hashes((godmode9_enc_crc32, godmode9_enc_md5, godmode9_enc_sha1, godmode9_enc_sha256, godmode9_enc_sha512, \
            godmode9_enc_sha3_512),
                         (calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1, calculated_enc_sha256, calculated_enc_sha512, \
            calculated_enc_sha3_512), "Godmode9 Encrypted")
        except ValueError as e:
            print("[WARNING] {}".format(e))




    gm9_txt_file_re = re.compile(r"{}\.txt".format(nds_name))

    for file in all_files_list:
        m = gm9_txt_file_re.match(file)
        if m:
            gm9_txt = pathlib.Path(file).resolve(strict=False).expanduser()
            break

    if gm9_txt:
        gm9_txt_cartid, gm9_version, gm9_txt_lines_list = parse_gm9_txt(gm9_txt)
    else:
        print("[ERROR] Godmode9 cart info txt file not found in directory {}".format(working_directory))
        raise FileNotFoundError

    cartid = None
    if parsed_args.cartid is not None:
        cartid_regex = re.compile(r"(NTR|TWL)([0-9ABCDEF]{8})")
        cartid = parsed_args.cartid
        m = cartid_regex.match(cartid)
        if not m:
            print(f"[WARNING] {cartid} is not a valid cart id")
        else:
            cartid = cartid_regex.sub("", cartid)
    else:
        cartid = gm9_txt_cartid

    if cartid is None:
        print('[WARNING] "Cart ID" not found!')
        cartid = "[REQUIRED]"


    if parsed_args.no_box:
        box_barcode = "(Don't have the box)"
        box_serial = "(Don't have the box)"
    else:
        box_barcode = "OPTIONAL"
        box_serial = "OPTIONAL"

    if parsed_args.outfile:
        outfile = parsed_args.outfile
    else:
        outfile = os.path.join(working_directory, "no_intro_post.txt")

    with codecs.open(outfile, "w", "utf8") as outf:
        outf.write(no_intro_post_template.format(gm9_version, encrypted_crc32, encrypted_md5, encrypted_sha1, calculated_enc_sha256,
                                                 calculated_enc_sha512, calculated_enc_sha3_512, region, revision,
                                                 serial, decrypted_crc32, decrypted_md5, decrypted_sha1,
                                                 calculated_dec_sha256, calculated_dec_sha512, calculated_dec_sha3_512,
                                                 length, box_barcode, box_serial, cartid,
                                                 "".join(gm9_txt_lines_list), "\n".join(gameheader_lines_list)))

    # Do some image cleanup
    boxart_regex = re.compile(r"(boxart\.jpg)|(boxart_no_obi\.jpg)")
    jpg_regex = re.compile(r"\.jpg$", re.IGNORECASE)
    for file in all_files_list:
        if jpg_regex.search(file) and not boxart_regex.match(file):
            #clear_exif(os.path.join(working_directory, file))
            print(os.path.join(working_directory, file))

    clear_tif_documentname(os.path.join(working_directory, "RAW"))
    clear_tif_documentname(working_directory)
