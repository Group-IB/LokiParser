import dpkt
import sys
from aplib.aplib import decompress
import hexdump
import json


parsed_payload = {}
parsed_payload['Network'] = {}
parsed_payload['Compromised Host/User Data'] = {}
parsed_payload['Malware Artifacts/IOCs'] = {}
parsed_payload['Applications'] = {}


def getWord(data, index):
    len = 2
    word = int.from_bytes(data[index:index + len], byteorder=sys.byteorder)
    return word


def getDWord(data, index):
    len = 4
    word = int.from_bytes(data[index:index + len], byteorder=sys.byteorder)
    return word


def getString(data, index, len):
    string = data[index:index + len]
    return string.decode('utf-8')


REPORT_HEADER = b"PWDFILE0"
REPORT_PACKED_HEADER = b"PKDFILE0"
REPORT_CRYPTED_HEADER = b"CRYPTED0"
REPORT_LEN_LIMIT = 1024 * 1024 * 32
REPORT_VERSION = b"1.0"
report_password = b'Mesoamerica'
REPORT_MODULE_HEADER = b'\x02\x00MODU\x01\x01'
REPORT_ITEMHDR_ID = 0xbeef0000
module_systeminfo = 0x00000000


def getOSVersion(major, minor, product_type):
    ms_OS_dict = {}
    ms_OS_dict['10.0.1'] = 'Windows 10 Workstation'
    ms_OS_dict['10.0.2'] = 'Windows Server 2016 Domain Controller'
    ms_OS_dict['10.0.3'] = 'Windows Server 2016'
    ms_OS_dict['6.3.1'] = 'Windows 8.1 Workstation'
    ms_OS_dict['6.3.3'] = 'Windows Server 2012 R2'
    ms_OS_dict['6.3.2'] = 'Windows Server 2012 R2 Domain Controller'
    ms_OS_dict['6.2.1'] = 'Windows 8 Workstation'
    ms_OS_dict['6.2.2'] = 'Windows Server 2012 Domain Controller'
    ms_OS_dict['6.2.3'] = 'Windows Server 2012'
    ms_OS_dict['6.1.1'] = 'Windows 7 Workstation'
    ms_OS_dict['6.1.2'] = 'Windows Server 2008 R2 Domain Controller'
    ms_OS_dict['6.1.3'] = 'Windows Server 2008 R2'
    ms_OS_dict['6.0.1'] = 'Windows Vista Workstation'
    ms_OS_dict['6.0.2'] = 'Windows Server 2008 Domain Controller'
    ms_OS_dict['6.0.3'] = 'Windows Server 2008'
    ms_OS_dict['5.2.1'] = 'Windows XP 64-Bit Edition'
    ms_OS_dict['5.2.2'] = 'Windows Server 2003 Domain Controller'
    ms_OS_dict['5.2.3'] = 'Windows Server 2003'
    ms_OS_dict['5.1.1'] = 'Windows XP Workstation'
    return ms_OS_dict['%s.%s.%s' % (major, minor, product_type)]


def getApplicationFromID(id):
    app_dict = {}
    app_dict[0] = 'System Info'
    app_dict[1] = 'FAR Manager'
    app_dict[2] = 'Total Commander'
    app_dict[3] = 'WS_FTP'
    app_dict[4] = 'CuteFTP'
    app_dict[5] = 'FlashFXP'
    app_dict[6] = 'FileZilla'
    app_dict[7] = 'FTP Commander'
    app_dict[8] = 'BulletProof FTP'
    app_dict[9] = 'SmartFTP'
    app_dict[10] = 'TurboFTP'
    app_dict[11] = 'FFFTP'
    app_dict[12] = 'CoffeeCup FTP / Sitemapper'
    app_dict[13] = 'CoreFTP'
    app_dict[14] = 'FTP Explorer'
    app_dict[15] = 'Frigate3 FTP'
    app_dict[16] = 'SecureFX'
    app_dict[17] = 'UltraFXP'
    app_dict[18] = 'FTPRush'
    app_dict[19] = 'WebSitePublisher'
    app_dict[20] = 'BitKinex'
    app_dict[21] = 'ExpanDrive'
    app_dict[22] = 'ClassicFTP'
    app_dict[23] = 'Fling'
    app_dict[24] = 'SoftX'
    app_dict[25] = 'Directory Opus'
    app_dict[26] = 'FreeFTP / DirectFTP'
    app_dict[27] = 'LeapFTP'
    app_dict[28] = 'WinSCP'
    app_dict[29] = '32bit FTP'
    app_dict[30] = 'NetDrive'
    app_dict[31] = 'WebDrive'
    app_dict[32] = 'FTP Control'
    app_dict[33] = 'Opera'
    app_dict[34] = 'WiseFTP'
    app_dict[35] = 'FTP Voyager'
    app_dict[36] = 'Firefox'
    app_dict[37] = 'FireFTP'
    app_dict[38] = 'SeaMonkey'
    app_dict[39] = 'Flock'
    app_dict[40] = 'Mozilla'
    app_dict[41] = 'LeechFTP'
    app_dict[42] = 'Odin Secure FTP Expert'
    app_dict[43] = 'WinFTP'
    app_dict[44] = 'FTP Surfer'
    app_dict[45] = 'FTPGetter'
    app_dict[46] = 'ALFTP'
    app_dict[47] = 'Internet Explorer'
    app_dict[48] = 'Dreamweaver'
    app_dict[49] = 'DeluxeFTP'
    app_dict[50] = 'Google Chrome'
    app_dict[51] = 'Chromium / SRWare Iron'
    app_dict[52] = 'ChromePlus'
    app_dict[53] = 'Bromium (Yandex Chrome)'
    app_dict[54] = 'Nichrome'
    app_dict[55] = 'Comodo Dragon'
    app_dict[56] = 'RockMelt'
    app_dict[57] = 'K-Meleon'
    app_dict[58] = 'Epic'
    app_dict[59] = 'Staff-FTP'
    app_dict[60] = 'AceFTP'
    app_dict[61] = 'Global Downloader'
    app_dict[62] = 'FreshFTP'
    app_dict[63] = 'BlazeFTP'
    app_dict[64] = 'NETFile'
    app_dict[65] = 'GoFTP'
    app_dict[66] = '3D-FTP'
    app_dict[67] = 'Easy FTP'
    app_dict[68] = 'Xftp'
    app_dict[69] = 'RDP'
    app_dict[70] = 'FTP Now'
    app_dict[71] = 'Robo-FTP'
    app_dict[72] = 'Certificate'
    app_dict[73] = 'LinasFTP'
    app_dict[74] = 'Cyberduck'
    app_dict[75] = 'Putty'
    app_dict[76] = 'Notepad++'
    app_dict[77] = 'CoffeeCup Visual Site Designer'
    app_dict[78] = 'FTPShell'
    app_dict[79] = 'FTPInfo'
    app_dict[80] = 'NexusFile'
    app_dict[81] = 'FastStone Browser'
    app_dict[82] = 'CoolNovo'
    app_dict[83] = 'WinZip'
    app_dict[84] = 'Yandex.Internet / Ya.Browser'
    app_dict[85] = 'MyFTP'
    app_dict[86] = 'sherrod FTP'
    app_dict[87] = 'NovaFTP'
    app_dict[88] = 'Windows Mail'
    app_dict[89] = 'Windows Live Mail'
    app_dict[90] = 'Becky!'
    app_dict[91] = 'Pocomail'
    app_dict[92] = 'IncrediMail'
    app_dict[93] = 'The Bat!'
    app_dict[94] = 'Outlook'
    app_dict[95] = 'Thunderbird'
    app_dict[96] = 'FastTrackFTP'
    app_dict[97] = 'Bitcoin'
    app_dict[98] = 'Electrum'
    app_dict[99] = 'MultiBit'
    app_dict[100] = 'FTP Disk'
    app_dict[101] = 'Litecoin'
    app_dict[102] = 'Namecoin'
    app_dict[103] = 'Terracoin'
    app_dict[104] = 'Bitcoin Armory'
    app_dict[105] = 'PPCoin (Peercoin)'
    app_dict[106] = 'Primecoin'
    app_dict[107] = 'Feathercoin'
    app_dict[108] = 'NovaCoin'
    app_dict[109] = 'Freicoin'
    app_dict[110] = 'Devcoin'
    app_dict[111] = 'Frankocoin'
    app_dict[112] = 'ProtoShares'
    app_dict[113] = 'MegaCoin'
    app_dict[114] = 'Quarkcoin'
    app_dict[115] = 'Worldcoin'
    app_dict[116] = 'Infinitecoin'
    app_dict[117] = 'Ixcoin'
    app_dict[118] = 'Anoncoin'
    app_dict[119] = 'BBQcoin'
    app_dict[120] = 'Digitalcoin'
    app_dict[121] = 'Mincoin'
    app_dict[122] = 'Goldcoin'
    app_dict[123] = 'Yacoin'
    app_dict[124] = 'Zetacoin'
    app_dict[125] = 'Fastcoin'
    app_dict[126] = 'I0coin'
    app_dict[127] = 'Tagcoin'
    app_dict[128] = 'Bytecoin'
    app_dict[129] = 'Florincoin'
    app_dict[130] = 'Phoenixcoin'
    app_dict[131] = 'Luckycoin'
    app_dict[132] = 'Craftcoin'
    app_dict[133] = 'Junkcoin'
    return app_dict[id]


def rc4DecryptHex(key, pt):
    if key == '':
        return pt

    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    ct = []
    for char in pt:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        ct.append(chr(char ^ s[(s[i] + s[j]) % 256]))
    decrypted_text = ''.join(ct)
    data = decrypted_text.encode('raw_unicode_escape')
    return data


def rc4DecryptText(key, pt):
    if key == '':
        return pt
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key[i % len(key)])) % 256
        s[i], s[j] = s[j], s[i]

    i = j = 0
    ct = []
    for char in pt:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        ct.append(chr(char ^ s[(s[i] + s[j]) % 256]))
    decrypted_text = ''.join(ct)
    data = decrypted_text.encode('raw_unicode_escape')
    return data


def unpack_stream(packed_data, unpacked_len):
    if not unpacked_len:
        return ''

    if unpacked_len > REPORT_LEN_LIMIT:
        return ''

    unpacked_data = decompress(packed_data)

    leng = unpacked_data.__len__()

    if leng > REPORT_LEN_LIMIT:
        return ''

    if leng == unpacked_len:
        return unpacked_data
    else:
        return ''


def read_strlen(data, pos, leng):
    if pos + leng > len(str(data)) or leng < 0:
        return False

    if not leng:
        return ""

    p = pos
    pos += leng
    return data[p:p + leng]


def read_dword(data, index):
    if index + 4 > len(str(data)):
        return False
    dword = data[index:index + 4]
    return int.from_bytes(dword, byteorder=sys.byteorder)


def read_word(data, index):
    if index + 2 > len(data):
        return False
    unpacked_word = data[index:index + 2]
    return int.from_bytes(unpacked_word, byteorder=sys.byteorder)


def check_report_crypted_header_new(data):
    if len(str(data)) < 4:
        return False
    max_header_len = len(REPORT_CRYPTED_HEADER)
    rc4_key = data[0:4]
    encrypted_header = data[4:4 + max_header_len]
    decrypted_header = rc4DecryptHex(rc4_key, encrypted_header)

    return check_report_crypted_header_old(decrypted_header)


def check_report_crypted_header_old(data):
    if data[0:len(REPORT_CRYPTED_HEADER)] == REPORT_CRYPTED_HEADER:
        return True
    return False


def check_report_crypted_header(data):
    if check_report_crypted_header_new(data) or check_report_crypted_header_old(data):
        return True
    return False


def verify_new_file_header(data):
    if len(str(data)) < 4:
        return False

    max_header_len = max(len(REPORT_HEADER), len(REPORT_PACKED_HEADER), len(REPORT_CRYPTED_HEADER))
    rc4_key = data[0:4]
    encrypted_header = data[4:4 + max_header_len]
    decrypted_header = rc4DecryptHex(rc4_key, encrypted_header)
    return verify_old_file_header(decrypted_header)


def verify_old_file_header(data):
    if data[0:len(REPORT_HEADER)] == REPORT_HEADER:
        return True
    if data[0:len(REPORT_PACKED_HEADER)] == REPORT_PACKED_HEADER:
        return True
    if data[0:len(REPORT_CRYPTED_HEADER)] == REPORT_CRYPTED_HEADER:
        return True
    return False


def verify_report_file_header(data):
    if verify_new_file_header(data) or verify_old_file_header(data):
        return True
    return False


def import_app(data, index, name):
    id = read_word(data, index)
    index += 2
    id = id & 0xffff
    parsed_payload['Applications'].update({'Name': name})
    parsed_payload['Applications'].update({'Type': id})

    itemleng = read_word(data, index)
    index += 2
    count = 1
    while index < len(data):
        leng = read_dword(data, index)
        index += 4
        try:
            item = data[index:index + leng].decode('utf-8')
            parsed_payload['Applications'].update({count: item})
        except:
            item = str(data[index:index + leng]).replace("'", '"')
            parsed_payload['Applications'].update({count: item})
        index += leng
        count += 1


def import_system_info(data, index):
    id = read_word(data, index)
    index += 2
    id = id & 0xffff
    id = read_word(data, index)
    index += 2
    id = id & 0xffff

    itemleng = read_word(data, index)
    index += 2
    leng = read_dword(data, index)
    index += 4
    version_info = data[index:index + leng]
    index += leng

    is_win64 = read_dword(data, index)
    index += 4

    leng = read_dword(data, index)
    index += 4
    user_country = data[index:index + leng].decode('utf-8')
    index += leng

    leng = read_dword(data, index)
    index += 4
    user_language = data[index:index + leng].decode('utf-8')
    index += leng

    is_admin = read_dword(data, index)
    index += 4

    leng = read_dword(data, index)
    index += 4
    hwid = data[index:index + leng]
    hwid = hwid[4:len(hwid)].decode('utf-8')
    index += leng
    leng = read_dword(data, index)
    index += 4
    system_info = data[index:index + leng]
    if len(system_info) == 36:
        wProcessorArchitecture = read_word(system_info, 0)
    else:
        wProcessorArchitecture = 0
    system_index = 0
    dwOSVersionInfoSize = read_dword(version_info, system_index)
    system_index += 4

    if dwOSVersionInfoSize != len(version_info):
        return False

    dwMajorVersion = read_dword(version_info, system_index)
    system_index += 4
    dwMinorVersion = read_dword(version_info, system_index)
    system_index += 4
    dwBuildNumber = read_dword(version_info, system_index)
    system_index += 4
    dwPlatformId = read_dword(version_info, system_index)
    system_index += 4
    szCSDVersion = read_strlen(version_info, system_index, 128)
    system_index += 128
    wServicePackMajor = read_word(version_info, system_index)
    system_index += 2
    wServicePackMinor = read_word(version_info, system_index)
    system_index += 2
    wSuiteMask = read_word(version_info, system_index)
    system_index += 2
    wProductType = int.from_bytes(version_info[system_index:system_index + 1], byteorder=sys.byteorder)
    system_index += 1
    wReserved = version_info[system_index:system_index + 1]
    system_index += 1
    os_name = getOSVersion(dwMajorVersion, dwMinorVersion, wProductType)

    index += leng

    parsed_payload['Compromised Host/User Data'].update({'OS name': os_name})
    parsed_payload['Compromised Host/User Data'].update({'is_win64': is_win64})
    parsed_payload['Compromised Host/User Data'].update({'user_country': user_country})
    parsed_payload['Compromised Host/User Data'].update({'user_language': user_language})
    parsed_payload['Compromised Host/User Data'].update({'is_admin': is_admin})
    parsed_payload['Compromised Host/User Data'].update({'hwid': hwid})


def import_module(data, pos, debug):
    index = pos
    hdr_id = read_strlen(data, index, 8)
    index += 8

    if hdr_id != REPORT_MODULE_HEADER:
        return False

    mod_len = read_dword(data, index)

    if mod_len == 16:
        index += 8
        return index
    if mod_len < 16:
        return False
    if debug:
        print("Mod len: %s" % mod_len)
    index += 2
    mod_ver = read_word(data, index)
    if debug:
        print("Mod ver: %s" % mod_ver)
    index += 2
    mod_id = read_word(data, index)
    mod_id = getApplicationFromID(mod_id)
    if debug:
        print("Mod id: %s" % mod_id)
    index += 2

    module = data[index:index - 14 + mod_len]
    if mod_id == 'System Info':
        import_system_info(module, 0)
    else:
        import_app(module, 2, mod_id)

        count = parsed_payload['Applications'].get('Quantity')
        count += 1
        parsed_payload['Applications'].update({'Quantity': count})

    index += mod_len - 14

    return index


def rand_decrypt(data):
    if len(str(data)) < 4:
        return False
    rc4_key = data[0:4]
    data = rc4DecryptHex(rc4_key, data[4:len(str(data))])
    return data


def pre_decrypt_report(data):
    if verify_new_file_header(data):
        data = rand_decrypt(data)

    if data[0:len(REPORT_CRYPTED_HEADER)] != REPORT_CRYPTED_HEADER:
        return False
    if len(str(data)) == 0:
        return False
    elif len(str(data)) < 12:
        return False
    elif len(str(data)) > REPORT_LEN_LIMIT:
        return False
    elif len(str(data)) == 12:
        return False

    encrypted_data = data[8:-4]
    decrypted_data = rc4DecryptHex(report_password, encrypted_data)
    return decrypted_data


def process_report_data(data, debug):
    index = 0
    if len(str(data)) == 0:
        return False
    elif len(str(data)) < 12:
        return False
    elif len(str(data)) > REPORT_LEN_LIMIT:
        return False
    elif len(str(data)) == 12:
        return True

    if verify_new_file_header(data):
        rand_decrypt(data)

    report_id = read_strlen(data, index, 8)
    index += 8

    if report_id == REPORT_CRYPTED_HEADER:
        parsed_payload['Malware Artifacts/IOCs'].update({'Crypted': report_id.decode('utf-8')})
        decrypted_data = rc4DecryptText(report_password, data[index:len(str(data))])
        data = decrypted_data
        index = 0
        report_id = read_strlen(data, index, 8)
        index += 8

    if report_id == REPORT_PACKED_HEADER:
        parsed_payload['Malware Artifacts/IOCs'].update({'Packed': report_id.decode('utf-8')})
        unpacked_len = read_dword(data, index)
        index += 4
        leng = read_dword(data, index)
        index += 4
        if leng < 0:
            return False
        if not leng:
            return ""
        if index + leng > len(str(data)):
            return False
        packed_data = data[index:index + leng]
        index += leng
        if unpacked_len > REPORT_LEN_LIMIT or len(str(packed_data)) > REPORT_LEN_LIMIT:
            return False
        if not len(str(packed_data)):
            return False
        if len(str(packed_data)):
            data = unpack_stream(packed_data, unpacked_len)
        if not len(str(data)):
            return False
        if len(str(data)) > REPORT_LEN_LIMIT:
            return False
        index = 0
        report_id = read_strlen(data, index, 8)
        index += 8
    if report_id != REPORT_HEADER:
        print("No header")
        return False
    version_id = read_strlen(data, index, 3)
    index += 8
    if version_id != REPORT_VERSION:
        return False
    parsed_payload['Malware Artifacts/IOCs'].update({'Data version': version_id.decode('utf-8')})
    if debug:
        hexdump.hexdump(data)
    report_version_id = version_id
    parsed_payload['Applications'].update({'Quantity': 0})
    while index < len(data):
        index = import_module(data, index, debug)

    return data


def parse(data, debug):
    if verify_report_file_header(data):
        report_new_encryption = False

        if verify_new_file_header(data):
            report_new_encryption = True

        if check_report_crypted_header(data) or verify_new_file_header(data):
            data = pre_decrypt_report(data)
            process_report_data(data, debug)


def getpkt(path, debug):
    pcap = dpkt.pcap.Reader(path)
    req = 0
    resp = 0
    http = 0
    httpheader = ""
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        """
        if not isinstance(eth.data, dpkt.ip.IP):
            ip = dpkt.ip.IP(buf)
        else:
        """
        ip = eth.data
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            try:
                if tcp.dport == 80 and len(tcp.data) > 0:  # HTTP REQUEST
                    if str(tcp.data).find('POST') != -1:
                        http += 1
                        httpheader = tcp.data
                        continue
                    else:
                        if httpheader != "":
                            pkt = httpheader + tcp.data
                            req += 1
                            request = dpkt.http.Request(pkt)
                            parsed_payload['Network'].update({'Request method': request.method})
                            uri = request.headers['host'] + request.uri
                            parsed_payload['Network'].update({'CnC': uri})
                            parsed_payload['Network'].update({'User-agent': request.headers['user-agent']})
                            if uri.find("gate.php") != -1:
                                parsed_payload['Network'].update({'Traffic Purpose': "Exfiltrate Stolen Data"})
                                parse(tcp.data, debug)
                            elif uri.find(".exe") != -1:
                                parsed_payload['Network'].update({'Traffic Purpose': "Download additional malware"})
                            print(json.dumps(parsed_payload, ensure_ascii=False, sort_keys=False, indent=4))
                            parsed_payload['Network'].clear()
                            parsed_payload['Malware Artifacts/IOCs'].clear()
                            parsed_payload['Compromised Host/User Data'].clear()
                            parsed_payload['Applications'].clear()
                            print("----------------------")
                if tcp.sport == 80 and len(tcp.data) > 0:  # HTTP RESPONCE
                    resp += 1
                    response = dpkt.http.Response(tcp.data)
                    if response.body.find(b'STATUS-IMPORT-OK') != -1:
                        AdMalw = True
                        print('Data imported successfully')
                    else:
                        print('C2 did not receive data')
                    print("----------------------")

            except(dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
    print("Requests: " + str(req))
    print("Responces: " + str(resp))
    path.close()
    return None


debug = False
path1 = r"C:\path\to\your\Loki.pcap"
f = open(path1, 'rb')
getpkt(f, debug)
