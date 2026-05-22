import requests
import json

data = {
  "logs": [
    {
      "event": "login",
      "time": "2024-12-08T23:45:00",
      "user": "m.chen@corp.net",
      "resource": "vpn_gateway",
      "metadata": {
        "src_ip": "98.42.115.7",
        "geo_location": "Home - San Jose, CA"
      }
    },
    {
      "event": "unusual_access_pattern",
      "time": "2024-12-08T23:52:00",
      "user": "m.chen@corp.net",
      "resource": "sharepoint_portal"
    }
  ]
}

# 1. upload
r = requests.post("http://localhost:8000/upload", files={"file": ("test.json", json.dumps(data), "application/json")})
print("Upload status:", r.status_code)

# 2. process
r = requests.post("http://localhost:8000/process", json={"manual_time": 1800.0})
print("Process status:", r.status_code)
if r.status_code != 200:
    print(r.text)
else:
    res = r.json()
    print("EVALUATION:", res.get("evaluation"))
