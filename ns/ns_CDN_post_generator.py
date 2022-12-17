import codecs
import os
from shutil import copyfile
import re
import subprocess
import tempfile
from zlib import crc32
from hashlib import sha1, sha256, sha512, md5, sha3_512

hactool_VER = "1.4.0"
hactool_path = "C:\\MyPrograms\\Utilities\\Switch\\hactool.exe"
nstool_VER = "1.4.1"
nstool_path = "C:\\MyPrograms\\Utilities\\Switch\\nstool.exe"
keys_path = "C:\\MyPrograms\\Utilities\\Switch\\prod.keys"

no_intro_post_template = """Dumped with GodMode v1.9.1 on an N3DS.
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


GameHeader output:
[code]
{}
[/code]
"""

def clear_exif(full_file_path):
    subprocess.run(["exiftool", "-overwrite_original", "-exif:all=", "-JFIF:all=", full_file_path], check=True)

def hash_nca_from_nsp(nsp_file_path):
    #hactool -t pfs0 "{}.nsp" - -outdir "{}"
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir_file = os.path.join(tmpdirname, os.path.split(nsp_file_path)[1])
        copyfile(nsp_file_path, tmpdir_file)
        cmd = [hactool_path, "-t", "pfs0", nsp_file_path, "--outdir", tmpdir_file]
        subprocess.run(cmd, check=True)



def get_encrypted_hashes(nds_file_path):
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir_file = os.path.join(tmpdirname, os.path.split(nds_file_path)[1])
        copyfile(nds_file_path, tmpdir_file)

        cmd = [ndecrypt_path, "e", tmpdir_file]
        subprocess.run(cmd, check=True)

        return hash_file(tmpdir_file)

def hash_file(full_file_path):
    calculated_crc32 = 0
    calculated_md5 = md5()
    calculated_sha1 = sha1()
    calculated_sha256 = sha256()
    calculated_sha512 = sha512()
    calculated_sha3_512 = sha3_512()
    with open(full_file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            calculated_crc32 = crc32(data, calculated_crc32)
            calculated_md5.update(data)
            calculated_sha1.update(data)
            calculated_sha256.update(data)
            calculated_sha512.update(data)
            calculated_sha3_512.update(data)

    output_crc32 = ("%08X" % calculated_crc32).upper()
    output_md5 = calculated_md5.hexdigest().upper()
    output_sha1 = calculated_sha1.hexdigest().upper()
    output_sha256 = calculated_sha256.hexdigest().upper()
    output_sha512 = calculated_sha512.hexdigest().upper()
    output_sha3_512 = calculated_sha3_512.hexdigest().upper()



    return output_crc32, output_md5, output_sha1, output_sha256, output_sha512, output_sha3_512


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


def generate(parsed_args):
    path_string_censor = "Path:               [EXPUNGED]"
    path_string_re = re.compile(r"Path:               ")

    gameheader_lines_list = []

    with codecs.open(parsed_args.gameheader_txt, "r", encoding="utf_16") as infile:
        for current_line in infile:
            current_line = current_line.rstrip("\r\n")
            if path_string_re.match(current_line):
                gameheader_lines_list.append(path_string_censor)
            else:
                gameheader_lines_list.append(current_line)


    length = -1
    decrypted_CRC32 = ""
    decrypted_MD5 = ""
    decrypted_SHA1 = ""
    serial = ""
    region = ""
    revision = ""
    encrypted_CRC32 = ""
    encrypted_MD5 = ""
    encrypted_SHA1 = ""

    length_re = re.compile("Length:             ([0-9]+)")
    decrypted_CRC32_re = re.compile(r"CRC32:              ([A-Z0-9]+)")
    decrypted_MD5_re = re.compile(r"MD5:                ([A-Z0-9]+)")
    decrypted_SHA1_re = re.compile(r"SHA1:               ([A-Z0-9]+)")
    serial_region_re = re.compile(r"Game Serial:        ([A-Z0-9]+) \(([a-zA-Z]+)\)")
    revision_re = re.compile("Version:            (.+)")
    encrypted_CRC32_re = re.compile(r"Encrypted CRC32:    ([A-Z0-9]+)")
    encrypted_MD5_re = re.compile(r"Encrypted MD5:      ([A-Z0-9]+)")
    encrypted_SHA1_re = re.compile(r"Encrypted SHA1:     ([A-Z0-9]+)")

    for line in gameheader_lines_list:
        m = length_re.match(line)
        if(m):
            length = m.group(1)

        m = decrypted_CRC32_re.match(line)
        if(m):
            decrypted_CRC32 = m.group(1)

        m = decrypted_MD5_re.match(line)
        if(m):
            decrypted_MD5 = m.group(1)

        m = decrypted_SHA1_re.match(line)
        if(m):
            decrypted_SHA1 = m.group(1)

        m = serial_region_re.match(line)
        if(m):
            serial = m.group(1)
            region = m.group(2)

        m = revision_re.match(line)
        if(m):
            revision = m.group(1)

        m = encrypted_CRC32_re.match(line)
        if(m):
            encrypted_CRC32 = m.group(1)

        m = encrypted_MD5_re.match(line)
        if(m):
            encrypted_MD5 = m.group(1)

        m = encrypted_SHA1_re.match(line)
        if(m):
            encrypted_SHA1 = m.group(1)

    calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1, calculated_dec_sha256, calculated_dec_sha512, \
        calculated_dec_sha3_512 = hash_file(parsed_args.nds_file)
    calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1, calculated_enc_sha256, calculated_enc_sha512, \
        calculated_enc_sha3_512 = get_encrypted_hashes(parsed_args.nds_file)

    check_hashes((calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1), (decrypted_CRC32, decrypted_MD5,
                                                                                   decrypted_SHA1), "Decrypted")
    check_hashes((calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1), (encrypted_CRC32, encrypted_MD5,
                                                                                   encrypted_SHA1), "Encrypted")

    if parsed_args.cartid is not None:
        cartid_regex = re.compile(r"(NTR|TWL)")
        cartid = parsed_args.cartid
        m = cartid_regex.match(cartid)
        if not m:
            pass
            #TODO: Do some proper cart id validation at some point
            #print(f"ERROR: {cartid} is not a valid cart id")
            #return
        else:
            cartid = cartid_regex.sub("", cartid)
    else:
        #TODO: Get cart id from file
        cartid = "[REQUIRED]"


    if parsed_args.no_box:
        box_barcode = "(Don't have the box)"
        box_serial = "(Don't have the box)"
    else:
        box_barcode = "OPTIONAL"
        box_serial = "OPTIONAL"

    with codecs.open(parsed_args.outfile, "w", "utf8") as outf:
        outf.write(no_intro_post_template.format(encrypted_CRC32, encrypted_MD5, encrypted_SHA1, calculated_enc_sha256,
                                                 calculated_enc_sha512, calculated_enc_sha3_512, region, revision,
                                                 serial, decrypted_CRC32, decrypted_MD5, decrypted_SHA1,
                                                 calculated_dec_sha256, calculated_dec_sha512, calculated_dec_sha3_512,
                                                 length, box_barcode, box_serial, cartid,
                                                 "\n".join(gameheader_lines_list)))

    #Do some image cleanup
    working_directory = os.path.split(parsed_args.nds_file)[0]
    all_files_list = os.listdir(working_directory)
    boxart_regex = re.compile(r"(boxart\.jpg)|(boxart_no_obi\.jpg)")
    jpg_regex = re.compile(r"\.jpg$", re.IGNORECASE)
    for file in all_files_list:
        if jpg_regex.search(file) and not boxart_regex.match(file):
            clear_exif(os.path.join(working_directory, file))
            print(os.path.join(working_directory, file))
