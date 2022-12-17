import codecs
import os
import pathlib
from shutil import copyfile
import re
import subprocess
import tempfile
from general.hash_utils import hash_file

ndecrypt_path = "C:\\MyPrograms\\Utilities\\3DS\\NDecrypt\\NDecrypt.exe"
ctrtool_path = "C:\\MyPrograms\\Utilities\\3DS\\ctrtool.exe"

no_intro_post_template = """
[OPTIONAL] DoM URL GOES HERE

Dumping tool and version: GodMode {gm9_ver} on an N3DS. Decrypted hashes were created with NDecrypt v0.2.2
Dumper: Icyelut
Affiliation: No-Intro 
Dump creation date: {dump_date}

Title: {game_title}
Title (native): {game_title_jp}
Region: Japan
Edition: [REQUIRED]
Languages: Japanese
Language Select: [CHECK THIS]

[code]
Serial: {serial} [CHECK THIS]
Revision: {revision}
Cart ID: {cartID}
Additional Cart Serial: REQUIRED

Encrypted ROM file info: >
Size: {enc_size}
CRC32: {enc_crc}
MD5: {enc_md5}
SHA-1: {enc_sha1}
SHA-256: {enc_sha256}
SHA512:   {enc_sha512}
SHA3-512: {enc_sha3512}

Decrypted ROM file info: >
Size: {dec_size}
CRC32: {dec_crc}
MD5: {dec_md5}
SHA-1: {dec_sha1}
SHA-256: {dec_sha256}
SHA512:   {dec_sha512}
SHA3-512: {dec_sha3512}


PCB Serial: [REQUIRED] ▼ •
ROM Chip Serial 1: [OPTIONAL]
Box Serial 1: [OPTIONAL]
Box Serial 2: [OPTIONAL]
Box Serial 3: [OPTIONAL]
Box Barcode: [OPTIONAL]

WikiData ID: [OPTIONAL]
[/code]


GodMode9 cart info txt:
[code]
{gm9_log}
[/code]


ctrtool output:
[code]
{ctrtool_log}
[/code]
"""


def clear_exif(full_file_path):
    subprocess.run(["exiftool", "-overwrite_original", "-exif:all=", "-JFIF:all=", full_file_path], check=True)


def get_encrypted_hashes(nds_file_path):
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir_file = os.path.join(tmpdirname, os.path.split(nds_file_path)[1])
        copyfile(nds_file_path, tmpdir_file)

        print(f"Encrypting {nds_file_path}...")
        cmd = [ndecrypt_path, "e", tmpdir_file]
        subprocess.run(cmd, check=True)

        print(f"Hashing {tmpdir_file}...")
        size = os.path.getsize(nds_file_path)
        return size, *hash_file(tmpdir_file)

def get_decrypted_hashes(nds_file_path):
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir_file = os.path.join(tmpdirname, os.path.split(nds_file_path)[1])
        copyfile(nds_file_path, tmpdir_file)

        print(f"Decrypting {nds_file_path}...")
        cmd = [ndecrypt_path, "d", tmpdir_file]
        subprocess.run(cmd, check=True)

        print(f"Hashing {tmpdir_file}...")
        size = os.path.getsize(nds_file_path)
        return size, *hash_file(tmpdir_file)

def get_ctrtool_log(three_ds_file_path):
    cmd = [ctrtool_path, "--intype=cci", "--verify", three_ds_file_path]
    completed_process_obj = subprocess.run(cmd, check=True, capture_output=True)

    if completed_process_obj.returncode == 0:
        return completed_process_obj.stdout.decode("utf8").splitlines()
    else:
        raise ValueError(f"ctrtool returned a non-zero exit code ({completed_process_obj.returncode})")

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
    path_string_re = re.compile(r"Path: {15}")

    three_ds_file = None
    if parsed_args.file:
        working_directory = os.path.split(parsed_args.file)[0]
        working_directory = os.path.split(working_directory)[0]
        three_ds_file = parsed_args.file
    else:
        working_directory = parsed_args.dir
        three_ds_file_re = re.compile(r"\.3ds$", re.IGNORECASE)
        for root, dirs, files in os.walk(working_directory):
            for file in files:
                if three_ds_file_re.search(file):
                    three_ds_file = pathlib.Path(os.path.join(root, file)).resolve(strict=False).expanduser()
                    break

    os.chdir(working_directory)

    if three_ds_file is None:
        print(f"[ERROR] 3ds file not found in directory {working_directory}")
        raise FileNotFoundError


    all_files_list = os.listdir(working_directory)
    ctrtool_lines_list = get_ctrtool_log(three_ds_file)

    serial = ""
    region = ""
    revision = ""
    crypto_key = ""


    crypto_key_re = re.compile(" > Crypto Key           (Secure) \(1\)")

    for line in ctrtool_lines_list:
        m = crypto_key_re.match(line)
        if m:
            crypto_key = m.group(1)


    if crypto_key == "":
        pass
        #raise ValueError(f"ERROR: Not an encrypted ROM file! Crypto Key: {crypto_key}")

    dec_size, calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1, calculated_dec_sha256, calculated_dec_sha512, \
        calculated_dec_sha3_512 = get_decrypted_hashes(three_ds_file)
    print(f"Hashing {three_ds_file}...")
    calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1, calculated_enc_sha256, calculated_enc_sha512, \
        calculated_enc_sha3_512 = hash_file(three_ds_file)
    enc_size = os.path.getsize(three_ds_file)

    #check_hashes((calculated_dec_crc32, calculated_dec_md5, calculated_dec_sha1), (decrypted_crc32, decrypted_md5,
    #                                                                               decrypted_sha1), "Decrypted")
    #check_hashes((calculated_enc_crc32, calculated_enc_md5, calculated_enc_sha1), (encrypted_crc32, encrypted_md5,
    #                                                                               encrypted_sha1), "Encrypted")

    title_id_re = re.compile("Title ID     : (.*)")
    product_code_re = re.compile("Product Code : (.*)")
    revision_re = re.compile("Revision     : (.*)")
    cartid_re = re.compile("Cart ID      : (.*)")
    platform_re = re.compile("Platform     : (.*)")
    savetype_re = re.compile("Save Type    : (.*)")
    save_chip_id_re = re.compile("Save chip ID : (.*)")
    timestamp_re = re.compile("Timestamp    : (.*)")
    gm9_version_re = re.compile("GM9 Version  : (.*)")

    if parsed_args.gm9_log:
        gm9_log_file = parsed_args.gm9_log
    else:
        for file in all_files_list:
            if file == f"{os.path.splitext(os.path.basename(three_ds_file))[0]}.txt":
                gm9_log_file = file
                break

    with open(gm9_log_file) as infile:
        for line in infile:
            m = title_id_re.match(line)
            if m:
                title_id = m.group(1)

            m = product_code_re.match(line)
            if m:
                product_code = m.group(1)

            m = revision_re.match(line)
            if m:
                revision = m.group(1)

            m = cartid_re.match(line)
            if m:
                cartid = m.group(1)

            m = platform_re.match(line)
            if m:
                platform = m.group(1)

            m = savetype_re.match(line)
            if m:
                savetype = m.group(1)

            m = save_chip_id_re.match(line)
            if m:
                save_chip_id = m.group(1)

            m = timestamp_re.match(line)
            if m:
                timestamp = m.group(1)

            m = gm9_version_re.match(line)
            if m:
                gm9_version = m.group(1)

    with open(gm9_log_file) as infile:
        gm9_log_text = infile.readlines()

    if cartid is None:
        print('[WARNING] "Cart ID" not found!')
        cartid = "[REQUIRED]"

    if revision is None:
        print('[WARNING] "Revision" not found!')
        revision = "[REQUIRED]"

    if gm9_version is None:
        print('[WARNING] "GM9 Version" not found!')
        gm9_version = "[REQUIRED]"

    if timestamp is None:
        print('[WARNING] "Timestamp" not found!')
        timestamp = "[REQUIRED]"

    if parsed_args.no_box:
        box_barcode = "(Don't have the box)"
        box_serial = "(Don't have the box)"
    else:
        box_barcode = "OPTIONAL"
        box_serial = "OPTIONAL"

    with codecs.open(parsed_args.outfile, "w", "utf8") as outf:
        filled_template = no_intro_post_template.format(gm9_ver=gm9_version,
                                                        dump_date=timestamp,
                                                        game_title="[REQUIRED]",
                                                        game_title_jp="[REQUIRED]",
                                                        enc_size=enc_size,
                                                        enc_crc=calculated_enc_crc32,
                                                        enc_md5=calculated_enc_md5,
                                                        enc_sha1=calculated_enc_sha1,
                                                        enc_sha256=calculated_enc_sha256,
                                                        enc_sha512=calculated_enc_sha512,
                                                        enc_sha3512=calculated_enc_sha3_512,
                                                        dec_size=dec_size,
                                                        dec_crc=calculated_dec_crc32,
                                                        dec_md5=calculated_dec_md5,
                                                        dec_sha1=calculated_dec_sha1,
                                                        dec_sha256=calculated_dec_sha256,
                                                        dec_sha512=calculated_dec_sha512,
                                                        dec_sha3512=calculated_dec_sha3_512,
                                                        serial=serial,
                                                        revision=revision,
                                                        cartID=cartid,
                                                        gm9_log="".join(gm9_log_text),
                                                        ctrtool_log="\n".join(ctrtool_lines_list))
        outf.write(filled_template)
        # outf.write(no_intro_post_template.format(encrypted_crc32, encrypted_md5, encrypted_sha1, calculated_enc_sha256,
        #                                          calculated_enc_sha512, calculated_enc_sha3_512, region, revision,
        #                                          serial, decrypted_crc32, decrypted_md5, decrypted_sha1,
        #                                          calculated_dec_sha256, calculated_dec_sha512, calculated_dec_sha3_512,
        #                                          length, box_barcode, box_serial, cartid,
        #                                          "\n".join(ctrtool_lines_list)))

    # Do some image cleanup
    boxart_regex = re.compile(r"(boxart\.jpg)|(boxart_no_obi\.jpg)")
    jpg_regex = re.compile(r"\.jpg$", re.IGNORECASE)
    for file in all_files_list:
        if jpg_regex.search(file) and not boxart_regex.match(file):
            clear_exif(os.path.join(working_directory, file))
            print(os.path.join(working_directory, file))
