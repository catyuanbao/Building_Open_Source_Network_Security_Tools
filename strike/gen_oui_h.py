import requests
from tqdm import tqdm


ALL_OUI_LINES = []
OUI_MAP_LINES = []


def parse_data(data):
    str_data = data.decode("utf-8", errors='ignore')
    for line in str_data.split('\n'):
        if '(hex)' in line:
            ALL_OUI_LINES.append(line)


def download_without_writing(url='https://standards-oui.ieee.org/'):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))

    with tqdm(
        desc="Downloading",
        total=total_size,
        unit='iB',
        unit_scale=True,
        unit_divisor=1024,
    ) as progress_bar:
        for data in response.iter_content(chunk_size=1024):
            parse_data(data)
            progress_bar.update(len(data))



def head_oui_url(url='https://standards-oui.ieee.org/'):
    """get current oui data time"""
    try:
        resp = requests.request('head', url)
        return resp.headers.get('Last-Modified')
    except Exception as error:
        print("head oui url error", error)

    return None


def load_last_modified():
    """load last download version of oui data time"""
    last_modified_date = ''
    try:
        with open('oui_url_last_modifed.txt') as fd:
            for line in fd:
                last_modified_date = line.strip()
        return last_modified_date
    except Exception as error:
        print('load last modified error', error)
        return last_modified_date


def save_last_modified(cur_last_modified):
    """save last modified"""
    lines = [cur_last_modified]
    with open('oui_url_last_modifed.txt', 'w') as fd:
        fd.writelines(lines)


def format_string(line):
    line = line.replace("(hex)", '')
    words = line.split()
    mac_addr = words[0].split('-')
    company = ' '.join(words[1:])
    format_str = '\t{{ {{0x{0}, 0x{1}, 0x{2}}}, "{3}" }},\n'
    if len(mac_addr) == 3 and company and len(mac_addr[0]) and len(mac_addr[1]) and len(mac_addr[2]):
        OUI_MAP_LINES.append(format_str.format(mac_addr[0], mac_addr[1], mac_addr[2], company))

    # make order so that binary search works
    OUI_MAP_LINES.sort()


def gen_oui_h_file():
    for line in ALL_OUI_LINES:
        try:
            format_string(line)
        except:
            import traceback;traceback.print_exc()
            pass

    lines = [
        "struct oui {\n",
        "    u_char prefix[3];       /* 24 bit global prefix */ \n",
        "    char *vendor;           /* vendor id string */ \n",
        "};\n\n"

        "struct oui oui_table[] = {\n",
    ]

    for line in OUI_MAP_LINES:
        lines.append(line)

    lines.append("};\n\n")

    with open("oui.h", "w") as fd:
        fd.writelines(lines)


if __name__ == '__main__':
    cur_last_modified = head_oui_url()
    last_modifed = load_last_modified()
    if cur_last_modified != last_modifed:
        download_without_writing()
        gen_oui_h_file()
        save_last_modified(cur_last_modified)
    else:
        print('no need update file')
        exit(0)
