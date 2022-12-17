import binascii
import codecs
import os
import sys
import traceback
import pathlib
from shutil import copyfile
import re
import subprocess
import tempfile
import urllib.request
from urllib.parse import urlsplit
import posixpath
import ssl
import json
from time import sleep
from general.hash_utils import hash_file, hash_directory_recursive

context = None

ndecrypt_path = "C:\\MyPrograms\\Utilities\\3DS\\NDecrypt\\NDecrypt.exe"

hash_excluded_files_list = [r"\.tik$", r"cetk", r"\.txt$"]

sleep_minutes = 5

file_info_template = """File: {}
    Size:     {}
    CRC32:    {}
    MD5:      {}
    SHA1:     {}
    SHA256:   {}
    SHA512:   {}
    SHA3-512: {}
"""


def clear_exif(full_file_path):
    subprocess.run(["exiftool", "-overwrite_original", "-exif:all=", "-JFIF:all=", full_file_path], check=True)

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

def extract_title_id_from_ticket(full_ticket_file_path):
    with codecs.open(full_ticket_file_path, "rb") as infile:
        # Get signature type so we know where the signature data ends
        sig_type = infile.read(4)
        if sig_type == b'\x00\x01\x00\x00':
            # RSA_4096 SHA1 (Unused for 3DS)
            sig_size = int.from_bytes(bytes.fromhex('023C'), "big", signed=False)
        elif sig_type == b'\x00\x01\x00\x01':
            # RSA_2048 SHA1 (Unused for 3DS)
            sig_size = int.from_bytes(bytes.fromhex('013C'), "big", signed=False)
        elif sig_type == b'\x00\x01\x00\x02':
            # Elliptic Curve with SHA1 (Unused for 3DS)
            sig_size = int.from_bytes(bytes.fromhex('7C'), "big", signed=False)
        elif sig_type == b'\x00\x01\x00\x03':
            # RSA_4096 SHA256
            sig_size = int.from_bytes(bytes.fromhex('023C'), "big", signed=False)
        elif sig_type == b'\x00\x01\x00\x04':
            # RSA_2048 SHA256
            sig_size = int.from_bytes(bytes.fromhex('013C'), "big", signed=False)
        elif sig_type == b'\x00\x01\x00\x05':
            # ECDSA with SHA256
            sig_size = int.from_bytes(bytes.fromhex('7C'), "big", signed=False)

        # Skip over the signature data
        infile.seek(sig_size, 1)
        # Jump to title id offset
        infile.seek(156, 1)

        title_id_bytes = infile.read(8)
        title_id_string = title_id_bytes.hex().upper()
        return title_id_string

def make_cdn_request(url, common_cert_path):
    req = urllib.request.Request(url)
    req.add_header('Accept', 'application/json')

    global context
    if context is None:
        context = ssl.create_default_context()
        # Don't verify server's cert
        context.check_hostname = False
        context.verify_mode = ssl.VerifyMode.CERT_NONE

        context.load_cert_chain(common_cert_path)

    print("Sending CDN request {}".format(url))
    try:
        response = urllib.request.urlopen(req, context=context)
    except urllib.error.HTTPError as e:
        print(e)
        response = e
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        raise e


    return response

def retrieve_store_page_from_cdn(ns_uid_str, common_cert_path):
    url = "https://samurai.ctr.shop.nintendo.net/samurai/ws/JP/title/{}?shop_id=1".format(ns_uid_str)
    response = make_cdn_request(url, common_cert_path)

    # TODO: Handle items that return type "D" (DLC) on the id_pair endpoint that don't have a store page (in-app purchase?)
    if response.status == 200:
        response_bytes = response.read()
        json_parsed = json.loads(response_bytes)

    else:
        print("WARNING: Unable to retrieve store page: '{}'".format(url))
        print("\n\tHTTP Status Code: '{} {}'".format(response.status, response.msg))
        response_bytes = response.read().decode("utf8")
        print("\n\tresponse='{}'".format(response_bytes))

        # TODO: Handle more CDN error codes
        if response.code == 404:
            error_parsed = json.loads(response_bytes)
            if 'error' in error_parsed:
                if 'code' in error_parsed['error']:
                    if error_parsed['error']['code']:
                        print('WARNING: Got CDN error code #3021, "This software is currently unavailable."')

        json_parsed = None

    return json_parsed

def make_full_dir(path):
    try:
        os.makedirs(path)
    except FileExistsError:
        pass

def download_images(store_page_json, title_id, ns_uid, download_directory, common_cert_path):
    image_urls = []

    if 'title' in store_page_json:
        if 'icon_url' in store_page_json['title']:
            image_urls.append(store_page_json['title']['icon_url'])

        if 'screenshots' in store_page_json['title']:
            if 'screenshot' in store_page_json['title']['screenshots']:
                for screenshot in store_page_json['title']['screenshots']['screenshot']:
                    if 'image_url' in screenshot:
                        for image_url in screenshot['image_url']:
                            if 'value' in image_url:
                                image_urls.append(image_url['value'])

        if 'top_image' in store_page_json['title']:
            if 'url' in store_page_json['title']['top_image']:
                image_urls.append(store_page_json['title']['top_image']['url'])

        if 'main_images' in store_page_json['title']:
            if 'image' in store_page_json['title']['main_images']:
                for image_obj in store_page_json['title']['main_images']['image']:
                    if 'image_url' in image_obj:
                        for image_url_item in image_obj['image_url']:
                            if 'value' in image_url_item:
                                image_urls.append(image_url_item['value'])

        if 'demo_available' in store_page_json['title']:
            if store_page_json['title']['demo_available']:
                if 'demo_titles' in store_page_json['title']:
                    if 'demo_title' in store_page_json['title']['demo_titles']:
                        for demo_title_obj in store_page_json['title']['demo_titles']['demo_title']:
                            if 'icon_url' in demo_title_obj:
                                image_urls.append(demo_title_obj['icon_url'])

        if 'thumbnails' in store_page_json['title']:
            if 'thumbnail' in store_page_json['title']['thumbnails']:
                for thumbnail in store_page_json['title']['thumbnails']['thumbnail']:
                    if 'url' in thumbnail:
                        image_urls.append(thumbnail['url'])

        if 'package_url' in store_page_json['title']:
            image_urls.append(store_page_json['title']['package_url'])

#        if 'movies' in store_page_json['title']:
#            if 'movie' in store_page_json['title']['movies']:
#                for movie_obj in store_page_json['title']['movies']['movie']

    for image_url in image_urls:
        response = response = make_cdn_request(image_url, common_cert_path)
        if response.status == 200:
            filename = posixpath.basename(urlsplit(image_url).path)
            subpath = "{}_{}_media".format(title_id, ns_uid)
            dir_path = os.path.join(download_directory, subpath)
            filepath = os.path.join(dir_path, filename)
            make_full_dir(dir_path)

            # Don't clobber
            # TODO: Give user more options for overwriting files
            if not os.path.isfile(filepath):
                with open(filepath, "wb") as outfile:
                    response_bytes = response.read()
                    outfile.write(response_bytes)

            # TODO: Change name based on type of image
            # TODO: Verify SHA256 in filename matches data


def extract_title_from_store_page(store_page_json):
    title = ""
    name = ""
    if 'title' in store_page_json:
        if 'formal_name' in store_page_json['title']:
            title = store_page_json['title']['formal_name']
        if 'name' in store_page_json['title']:
            name = store_page_json['title']['name']

    print("'formal_name': '{}', 'name': '{}'".format(title, name))

    return title

def extract_product_code_from_store_page(store_page_json):
    product_code = ""
    if 'title' in store_page_json:
        if 'product_code' in store_page_json['title']:
            product_code = store_page_json['title']['product_code']

    return product_code

def extract_languages_from_store_page(store_page_json):
    language_list = []
    if 'title' in store_page_json:
        if 'languages' in store_page_json['title']:
            if 'language' in store_page_json['title']['languages']:
                language_list = store_page_json['title']['languages']['language']

    return language_list

def retrieve_metadata_from_cdn(ns_uid, title_id, images_download_path, common_cert_path):
    store_page_json = retrieve_store_page_from_cdn(ns_uid, common_cert_path)
    if store_page_json:
        with codecs.open("{}_{}.json".format(title_id, ns_uid), "w", "utf8") as outfile:
            outfile.write(json.dumps(store_page_json, sort_keys=True, indent=4))

        title = extract_title_from_store_page(store_page_json)
        product_code = extract_product_code_from_store_page(store_page_json)
        language_list = extract_languages_from_store_page(store_page_json)

        download_images(store_page_json, title_id, ns_uid, images_download_path, common_cert_path)
    else:
        title = ""
        product_code = ""
        language_list = []

    return title, product_code, language_list

def retrieve_ns_uid_from_cdn(ticket_file_path, common_cert_path):
    title_id = extract_title_id_from_ticket(ticket_file_path)

    url = "https://ninja.ctr.shop.nintendo.net/ninja/ws/titles/id_pair?title_id[]={}".format(title_id)

    print(url)

    response = make_cdn_request(url, common_cert_path)

    response_bytes = response.read()
    print(response_bytes)
    print(response_bytes.decode("UTF8"))
    json_parsed = json.loads(response_bytes)


    success = False
    ns_uid = ""
    if response.status == 200:
        if 'title_id_pairs' in json_parsed:
            if 'title_id_pair' in json_parsed['title_id_pairs']:
                if len(json_parsed['title_id_pairs']['title_id_pair']) == 1:
                    if 'ns_uid' in json_parsed['title_id_pairs']['title_id_pair'][0]:
                        ns_uid = json_parsed['title_id_pairs']['title_id_pair'][0]['ns_uid']
                        success = True

    return success, ns_uid


def get_title_id_from_ctrcdnfetch_output(stdout):
    title_id_regex = re.compile(r"Downloading Title ID ([A-Z0-9]+)")

    m = re.search(title_id_regex, stdout.decode("utf8"))

    if m:
        title_id = m.group(1)
    else:
        title_id = None

    return title_id

def download_content_from_cdn(ctrcdn_path, full_ticket_file_path, target_path):
    make_full_dir(target_path)
    completed_process_obj = subprocess.run([ctrcdn_path, "-r", full_ticket_file_path], cwd=target_path, capture_output=True, check=True)

    title_id = get_title_id_from_ctrcdnfetch_output(completed_process_obj.stdout)
    if title_id:
        content_dir_path = os.path.join(target_path, title_id)
        headers_file_path = os.path.join(content_dir_path, "HTTP_headers.txt")
        with open(headers_file_path, "wb") as outfile:
            # TODO: Fix cURL carriage return weirdness
            outfile.write(completed_process_obj.stdout)
    else:
        # TODO: More robust checking of ctrcdnfetch output
        print("WARNING: Couldn't get title ID from ctrcdnfetch output!")
        headers_file_path = None

    return title_id, headers_file_path

def generate_for_ticket(parsed_args, ticket_path):
    title_id = extract_title_id_from_ticket(ticket_path)
    print("\n\nGot title ID from ticket: {}".format(title_id))
    success, ns_uid = retrieve_ns_uid_from_cdn(ticket_path, parsed_args.cert_path)
    print("ns_uid: {}".format(ns_uid))
    if ns_uid != "":
        title, internal_product_code, languages = retrieve_metadata_from_cdn(ns_uid, title_id, parsed_args.download_dir, parsed_args.cert_path)
    else:
        print("WARNING: This ticket doesn't have an ns_uid associated with it, or wrong region")
        title = "[REQUIRED]"
        internal_product_code = ""
        languages = []

    print(title)
    print(internal_product_code)
    print(languages)

    if not parsed_args.only_metadata:
        print("\nRunning ctrcdnfetch...")
        ctrcdnfetch_titleid, headers_file_path = download_content_from_cdn(parsed_args.ctrcdnfetch_path, ticket_path, parsed_args.download_dir)
        if ctrcdnfetch_titleid is None or ctrcdnfetch_titleid == "":
            print("ERROR: Failed to download content for ticket {}, aborting...".format(ticket_path))
            sys.exit(1)
        elif ctrcdnfetch_titleid != title_id:
            # TODO: Instead of quitting, handle same as missing store page
            print("ERROR: Title ID extracted via this script ({}) doesn't match the title ID output by ctrcdnfetch ({})".format(title_id, ctrcdnfetch_titleid))
            sys.exit(1)

    content_dir = os.path.join(parsed_args.download_dir, title_id)

    output_template = """\tFile: {}
        Size:     {}
        CRC32:    {}
        MD5:      {}
        SHA1:     {}
        SHA256:   {}
        SHA512:   {}
        SHA3-512: {}
    """

    file_info_list = []
    hash_list = hash_directory_recursive(content_dir, root_str="", exclude_re=hash_excluded_files_list)
    for item in hash_list:
        file_info_list.append(output_template.format(*item))

    file_info_output = "\n\n".join(file_info_list)

    if len(languages) > 0:
        language_output = ", ".join([language['iso_code'] for language in languages])
        language_output = language_output + " [VERIFY THIS]"
    else:
        language_output = "[REQUIRED]"

    no_intro_post_template = """
Title: [REQUIRED]
Title (native): {} [VERIFY THIS]
Region: Japan
Languages/Language Select: {}
Dump tools: GodMode v2.1.1 for ticket, ctrcdnfetch (203d526) for download and headers
Digital serial: {}

Format: CDN
[code]
{}
[/code]
    """
    no_intro_post_output = no_intro_post_template.format(title, language_output, title_id, file_info_output)

    with codecs.open(os.path.join(content_dir, "no-intro.txt"), "w", "utf8") as outfile:
        outfile.write(no_intro_post_output)


def get_all_tickets_in_dir(ticket_dir):
    tik_re = re.compile(r"\.tik$")
    return [os.path.join(ticket_dir, x) for x in os.listdir(ticket_dir) if tik_re.search(x)]


def move_ticket_to_done_folder(root_dir, tik_path):
    new_location_path = os.path.join(root_dir, "_done")
    make_full_dir(new_location_path)
    tik_filename = os.path.basename(tik_path)
    new_location_file = os.path.join(new_location_path, tik_filename)
    os.rename(tik_path, new_location_file)


def generate(parsed_args):
    global sleep_minutes
    if parsed_args.ticket_dir:
        # Batch mode
        tik_path_list = get_all_tickets_in_dir(parsed_args.ticket_dir)
        for tik_path in tik_path_list:
            generate_for_ticket(parsed_args, tik_path)
            move_ticket_to_done_folder(parsed_args.ticket_dir, tik_path)

            # Play nice
            print("Sleeping for {} minutes.".format(sleep_minutes))
            sleep(sleep_minutes * 60)
    else:
        # Single ticket mode
        generate_for_ticket(parsed_args, parsed_args.single_ticket_path)

