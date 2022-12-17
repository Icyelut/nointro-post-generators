import re

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