import requests
import json
import base64
from typing import List, Optional
from dataclasses import dataclass

APP_PASSWORD = "oAR80SGuX3EEjUGFRwLFKBTiris="

class SportzxClient:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Dalvik/2.1.0 (Linux; Android 13)", "Accept-Encoding": "gzip"})

    def _generate_aes_key_iv(self, s: str):
        CHARSET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+!@#$%&="
        def u32(x: int): return x & 0xFFFFFFFF
        data = s.encode("utf-8")
        n = len(data)
        u = 0x811c9dc5
        for b in data: u = u32((u ^ b) * 0x1000193)
        key = bytearray(16)
        for i in range(16):
            b = data[i % n]; u = u32(u * 0x1f + (i ^ b)); key[i] = CHARSET[u % len(CHARSET)]
        u = 0x811c832a
        for b in data: u = u32((u ^ b) * 0x1000193)
        iv = bytearray(16)
        idx = 0; acc = 0
        while idx != 0x30:
            b = data[idx % n]; u = u32(u * 0x1d + (acc ^ b)); iv[idx // 3] = CHARSET[u % len(CHARSET)]
            idx += 3; acc = u32(acc + 7)
        return bytes(key), bytes(iv)

    def _decrypt_data(self, b64_data: str):
        try:
            ct = base64.b64decode(b64_data)
            key, iv = self._generate_aes_key_iv(APP_PASSWORD)
            from Crypto.Cipher import AES
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            pad = pt[-1]
            if 1 <= pad <= 16: pt = pt[:-pad]
            return pt.decode("utf-8", errors="replace")
        except: return ""

    def _fetch_and_decrypt(self, url: str):
        try:
            r = self.session.get(url, timeout=self.timeout)
            r.raise_for_status()
            decrypted = self._decrypt_data(r.json().get("data", ""))
            return json.loads(decrypted) if decrypted else {}
        except: return {}

    def _get_api_url(self):
        try:
            r = self.session.post("https://firebaseinstallations.googleapis.com/v1/projects/sportzx-7cc3f/installations", json={"fid": "eOaLWBo8S7S1oN-vb23mkf", "appId": "1:446339309956:android:b26582b5d2ad841861bdd1", "authVersion": "FIS_v2", "sdkVersion": "a:18.0.0"}, headers={"User-Agent": "Dalvik/2.1.0", "x-goog-api-key": "AIzaSyBa5qiq95T97xe4uSYlKo0Wosmye_UEf6w"})
            auth_token = r.json()["authToken"]["token"]
            r2 = self.session.post("https://firebaseremoteconfig.googleapis.com/v1/projects/446339309956/namespaces/firebase:fetch", json={"appVersion": "2.1", "appInstanceId": "eOaLWBo8S7S1oN-vb23mkf", "appId": "1:446339309956:android:b26582b5d2ad841861bdd1", "packageName": "com.sportzx.live"}, headers={"User-Agent": "Dalvik/2.1.0", "X-Goog-Api-Key": "AIzaSyBa5qiq95T97xe4uSYlKo0Wosmye_UEf6w", "X-Goog-Firebase-Installations-Auth": auth_token})
            return r2.json().get("entries", {}).get("api_url")
        except: return None

    def get_json_data(self):
        api_url = self._get_api_url()
        if not api_url: return []
        
        final_json_data = []
        events = self._fetch_and_decrypt(f"{api_url.rstrip('/')}/events.json")
        
        for event in (events if isinstance(events, list) else []):
            eid = event.get("id")
            if not eid: continue
            
            # Extracting event and team details (Handling missing data safely)
            event_info = event.get("eventInfo", {})
            event_obj = {
                "Event details": event.get("title", "Unknown Event"),
                "Event logo": event.get("logo", ""),  # App may or may not provide this
                "Team a name": event_info.get("team1Name", ""),
                "Team a logo": event_info.get("team1Logo", ""),
                "Team b name": event_info.get("team2Name", ""),
                "Team b logo": event_info.get("team2Logo", ""),
                "Stream links": []
            }
            
            channels = self._fetch_and_decrypt(f"{api_url.rstrip('/')}/channels/{eid}.json")
            
            if isinstance(channels, list) and len(channels) > 0:
                stream_count = 1
                for ch in channels:
                    stream_url = ch.get("link", "").split("|")[0].strip()
                    api_val = ch.get("api", "")
                    
                    stream_obj = {
                        "Stream Number": stream_count,
                        "Name": ch.get("title", "Channel"),
                        "Url": stream_url if stream_url else "Link not available yet",
                        "Api": api_val if api_val else "No DRM Key"
                    }
                    event_obj["Stream links"].append(stream_obj)
                    stream_count += 1
            else:
                # If no links are available yet
                event_obj["Stream links"].append({
                    "Stream Number": 1,
                    "Name": "No links added yet",
                    "Url": "",
                    "Api": ""
                })
                
            final_json_data.append(event_obj)
            
        return final_json_data

def generate_json_file(data):
    with open("Sportzx.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print("JSON Generated Successfully!")

if __name__ == "__main__":
    client = SportzxClient()
    data = client.get_json_data()
    if data: generate_json_file(data)
