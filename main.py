import requests
import json

API_KEY = "<API>"
headers = {
    "Accept": "application/json",
    "x-apikey": API_KEY
}
malicious = []

print("...")
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
print("###")
