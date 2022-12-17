import argparse
import pathlib
import sys

from nds import nds_post_generator
from three_ds import three_ds_cdn_post_generator
from three_ds import three_ds_cart_post_generator
from ns import ns_cart_post_generator
from general import hash_utils, image_utils

def is_valid_new_file_location(file_path):

    path_maybe = pathlib.Path(file_path)
    path_resolved = None

    # try and resolve the path
    try:
        path_resolved = path_maybe.resolve(strict=False).expanduser()

    except Exception as e:
        raise argparse.ArgumentTypeError("Failed to parse `{}` as a path: `{}`".format(file_path, e))

    if not path_resolved.parent.exists():
        raise argparse.ArgumentTypeError("The parent directory of `{}` doesn't exist!".format(path_resolved))

    return path_resolved


def is_file(strict=True):
    def _is_file(file_path):

        path_maybe = pathlib.Path(file_path)
        path_resolved = None

        # try and resolve the path
        try:
            path_resolved = path_maybe.resolve(strict=strict).expanduser()

        except Exception as e:
            raise argparse.ArgumentTypeError("Failed to parse `{}` as a path: `{}`".format(file_path, e))

        # double check to see if its a file
        if strict:
            if not path_resolved.is_file():
                raise argparse.ArgumentTypeError("The path `{}` is not a file!".format(path_resolved))

        return path_resolved
    return _is_file


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate no-intro posts from roms",
        epilog="Copyright 2021-01-09 - Icyelut. GPLv3",
        fromfile_prefix_chars='@')

    parser.add_argument("--verbose", action="store_true", help="Increase logging verbosity")
    parser.add_argument('--outfile', dest="outfile", type=is_valid_new_file_location,
                                    help="Path and filename for the no-intro post txt")

    subparsers = parser.add_subparsers(help="Subcommand help")

    nds_parser = subparsers.add_parser("nds", help="Nintendo DS(i) mode")
    nds_parser.add_argument("--gameheader-txt", dest="gameheader_txt", required=False, type=is_file(True),
                            help="Text file containing the GameHeader output")
    nds_parser.add_argument("--nds-file", dest="nds_file", type=is_file(True),
                            help="Path to the nds file. Working directory will be changed to this path")
    nds_parser.add_argument("--cartid-txt", dest="cartid_txt", required=False, type=is_file(True),
                            help="Text file containing the cart ID from GodMode9")
    nds_parser.add_argument("--cartid", dest="cartid", required=False,
                            help="Cart ID from GodMode9 in the format (NTR|TWL)########")
    nds_parser.add_argument("--no-box", action="store_true", dest="no_box", required=False,
                            help="Automatically outputs 'Don't have box'")
    nds_parser.set_defaults(func_to_run=nds_post_generator.generate)

    three_ds_parser = subparsers.add_parser("3ds", help="Nintendo 3DS cart mode")
    three_ds_parser.add_argument("--file", dest="file", type=is_file(True),
                                 help="Path to the encrypted 3ds file. Working directory will be changed to this path")
    three_ds_parser.add_argument("--gm9_log", dest="gm9_log", type=is_file(True),
                                 help="Text file containing the cart info from GodMode9")
    three_ds_parser.add_argument("--no-box", action="store_true", dest="no_box", help="Automatically outputs 'Don't have box'")
    three_ds_parser.add_argument("dir", type=pathlib.Path, help="Directory that contains all the required files")
    three_ds_parser.set_defaults(func_to_run=three_ds_cart_post_generator.generate)

    three_ds_cdn_parser = subparsers.add_parser("3ds_cdn", help="3DS CDN mode")
    three_ds_cdn_parser.add_argument("--ticket", dest="single_ticket_path", type=is_file(True), required=False,
                            help=".tik file")
    three_ds_cdn_parser.add_argument("--ticket_dir", dest="ticket_dir", required=False,
                            help="Path containing tickets to process in batch mode")
    three_ds_cdn_parser.add_argument("--download_dir", dest="download_dir", required=False,
                            help="Path to store downloaded content")
    three_ds_cdn_parser.add_argument("--cert_path", dest="cert_path", required=False,
                            help="Path to 3DS common SSL cert. Needed to retrieve name from eShop")
    three_ds_cdn_parser.add_argument("--skip_name_retrieval", action="store_true", dest="skip_name_retrieval", required=False,
                            help="Don't retrieve name from eShop")
    three_ds_cdn_parser.add_argument("--only_metadata", action="store_true", dest="only_metadata", required=False,
                            help="Don't download content, only download metadata")
    three_ds_cdn_parser.add_argument("--ctrcdnfetch", dest="ctrcdnfetch_path", required=True,
                            help="Path to ctrcdnfetch executable")
    three_ds_cdn_parser.set_defaults(func_to_run=three_ds_cdn_post_generator.generate)

    ns_parser = subparsers.add_parser("ns", help="Nintendo Switch cart mode")
    ns_parser.add_argument("--xci-file", dest="xci_file", type=is_file(True),
                            help="Path to the xci file. Working directory will be changed to this path")
    ns_parser.add_argument("--no-box", action="store_true", dest="no_box", required=False,
                            help="Automatically outputs 'Don't have box'")
    ns_parser.set_defaults(func_to_run=ns_cart_post_generator.generate)

    hash_parser = subparsers.add_parser("hash", help="General hash mode")
    hash_parser.add_argument("--file", dest="infile", type=is_file(True),
                            help="File to hash")
    hash_parser.add_argument("--folder", dest="folder",
                            help="Path to folder with files to hash")
    hash_parser.set_defaults(func_to_run=hash_utils.generate)

    img_parser = subparsers.add_parser("img", help="General image utilities")
    img_parser.add_argument("--file", dest="infile", type=is_file(True),
                            help="Input file")
    img_parser.add_argument("--folder", dest="folder",
                            help="Path to folder with files to process")
    img_parser.add_argument("--tiff", action="store_true", dest="clear_document_name",
                            help="Erases the DocumentName EXIF tag on .tif files")
    img_parser.set_defaults(func_to_run=image_utils.run)

    parsed_args = parser.parse_args()

    if "func_to_run" in parsed_args:

        parsed_args.func_to_run(parsed_args)

    else:
        print("No function to run. Quitting.")
        parser.print_help()
        sys.exit(0)
