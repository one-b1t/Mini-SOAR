import os
import base64
import requests
import urllib3
from minisoar.config import load_env

load_env()
urllib3.disable_warnings()

base_url = "https://172.30.100.79:13299/api/v1.0"
user = os.getenv("KSC_USERNAME")
pwd = os.getenv("KSC_PASSWORD")

u_b64 = base64.b64encode(user.encode("utf-8")).decode("utf-8")
p_b64 = base64.b64encode(pwd.encode("utf-8")).decode("utf-8")

headers = {
    "Authorization": f'KSCBasic user="{u_b64}", pass="{p_b64}"',
    "Content-Type": "application/json",
}

r = requests.post(f"{base_url}/Session.StartSession", headers=headers, json={}, verify=False, timeout=5)
print("Login status:", r.status_code, r.text)
token = r.json().get("PxgRetVal")
print("Session token:", token)

# Test calling an API with the session token
auth_headers = {
    "X-KSC-Session": token,
    "Kaspersky-Session-Token": token,
    "Authorization": f"KSCSession {token}",
    "Content-Type": "application/json",
}

for ep in ["HostGroup.FindGroups", "ServerHierarchy.GetServerInfo", "Session.GetSessionInfo"]:
    try:
        r_ep = requests.post(f"{base_url}/{ep}", headers=auth_headers, json={}, verify=False, timeout=5)
        print(f"{ep} -> HTTP {r_ep.status_code} | {r_ep.text[:200]}")
    except Exception as e:
        print(f"{ep} -> Error {e}")
