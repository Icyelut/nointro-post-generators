import os
import re
import pathlib
from zlib import crc32
from hashlib import sha1, sha256, sha512, md5, sha3_512


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

    os.path.getsize(full_file_path)
    output_crc32 = ("%08X" % (calculated_crc32 & 0xffffffff)).upper()
    output_md5 = calculated_md5.hexdigest().upper()
    output_sha1 = calculated_sha1.hexdigest().upper()
    output_sha256 = calculated_sha256.hexdigest().upper()
    output_sha512 = calculated_sha512.hexdigest().upper()
    output_sha3_512 = calculated_sha3_512.hexdigest().upper()

    return output_crc32, output_md5, output_sha1, output_sha256, output_sha512, output_sha3_512


def hash_directory_recursive(full_path_to_dir, root_str=".", exclude_re=None, include_re=None):
    if root_str == "":
        separator = ""
    else:
        separator = os.sep

    hash_list = []
    for root, dirs, files in os.walk(full_path_to_dir):
        for file in files:
            if exclude_re:
                match = False
                for regex in exclude_re:
                    regex_comp = re.compile(regex)
                    if regex_comp.search(file):
                        match = True
                        break
                if match:
                    continue

            if include_re:
                match = False
                for regex in include_re:
                    regex_comp = re.compile(regex)
                    if regex_comp.search(file):
                        match = True
                        break
                if not match:
                    continue

            path_string = "{}{}{}".format(root.replace(full_path_to_dir, root_str), separator, file)
            full_path_to_file = pathlib.Path(os.path.join(full_path_to_dir, root, file)).resolve(strict=True).expanduser()
            size = os.path.getsize(full_path_to_file)
            hash_list.append((path_string, size, *hash_file(full_path_to_file)))

    return hash_list


def generate(parsed_args):
    output_template = """File: {}
    Size:     {}
    CRC32:    {}
    MD5:      {}
    SHA1:     {}
    SHA256:   {}
    SHA512:   {}
    SHA3-512: {}"""

    hash_list = hash_directory_recursive(parsed_args.folder)
    for item in hash_list:
        print("\n")
        print(output_template.format(*item))