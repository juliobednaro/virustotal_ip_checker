'''
References:
    https://www.virustotal.com/
    http://magic-cookie.co.uk/iplist.html
'''

import requests
import json
import re


class InvalidAddressOrMaskException(Exception):
    pass


class MagicCookie:
    REQ_URL = "http://magic-cookie.co.uk/cgi-bin/iplist-cgi.pl"
    REQ_HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    }
    ERROR_STR = "Invalid address or netmask"
    __response = None
    __response_text = None

    def __init__(self, ipw, ipx, ipy, ipz, mask):
        self.addresses = None
        self.ip_address_range = None
        self.addresses_number = None
        self.ipw = ipw
        self.ipx = ipx
        self.ipy = ipy
        self.ipz = ipz
        self.mask = mask

    def send_request(self):
        try:
            self.__response = requests.post(self.REQ_URL, headers=headers,
                                            data={
                                                "ipw": self.ipw,
                                                "ipx": self.ipx,
                                                "ipy": self.ipy,
                                                "ipz": self.ipz,
                                                "mask": self.mask
                                            })
            self.__response_text = self.__response.text
            if re.compile(self.ERROR_STR).search(self.__response_text):
                raise InvalidAddressOrMaskException

            self.parse_response()
        except InvalidAddressOrMaskException:
            print(self.ERROR_STR)
        except (AttributeError, IndexError):
            print("Failed to parse response data.")
        except Exception as e:
            print(str(e))

    def parse_response(self) -> list:
        self.addresses_number = re.compile(r"(?P<count>\d+?) addresses").search(self.__response_text).groups()[0]
        self.ip_address_range = re.compile(r"IP address range:\s(?P<range>.+?)\<br\>").search(self.__response_text).groups()[0]
        self.addresses = re.compile(r"(?<=<br>)(?P<addrs>\d+?\.\d+?\.\d+?\.\d+?)(?=<br>)").findall(self.__response_text)
        return self.addresses


API_KEY = "<API>"
headers = {
    "Accept": "application/json",
    "x-apikey": API_KEY
}
malicious = []


def enter_ip_list() -> str:
    return input("Enter IP (comma separated)")


def enter_ip_subnet() -> str:
    inp = input("Enter IP and subnet mask (e.g. 91.91.91.91/24)")
    rex = re.compile(r"^\d+?\.\d+?\.\d+?\.\d+?\/\d+$")
    return inp if rex.fullmatch(inp) else enter_ip_subnet()


def get_ip_list() -> tuple:
    ip_input = enter_ip_list()
    return tuple(ip_input.split(","))
'''
for i in range(256):
    IP = "162.142.125.{}".format(i)
    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(IP)
    response = requests.get(url, headers=headers)
    try:
        data = json.loads(response.text)
        data = data["data"]["attributes"]["last_analysis_stats"]
        mal, sus = data["malicious"], data["suspicious"]
        if mal > 0 or sus > 0:
            malicious.append(IP)
        print(IP, mal, sus)
    except:
        print("Failed fetching data for", IP)



with open("malicious.txt", "a") as file:
    for _ in malicious:
        file.write(_)
        file.write("\n")
'''


def get_ip_subnet() -> str:
    return enter_ip_subnet()


if __name__=="__main__":
    print("[1] Single/Multiple IPs")
    print("[2] Whole Subnet e.g. /24")
    mode = input("Which one?")

    if mode == "1":
        ip_list = get_ip_list()
    else:
        w, x, y, z, mask = re.split("[./]", get_ip_subnet())
        MagicCookie(w, x, y, z, mask).send_request()
