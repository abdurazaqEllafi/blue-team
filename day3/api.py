import os, time 
import requests 
BASE = "https://httpbin.org" 

response = requests.get(
    f"{BASE}/user-agent",
    timeout=5 
)

response.raise_for_status()
status = response.status_code
content = response.headers["content-type"]
data = response.json()
print (data['user-agent'])
print (status )
print (content)
