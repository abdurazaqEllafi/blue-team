import os, time 
import requests 
BASE = "https://httpbin.org" 


response1 = requests.post(
    f"{BASE}/response-headers",
    timeout=5 
)

response1.raise_for_status()
status = response1.status_code
content = response1.headers["content-type"]
data = response1.json()
print (data ['Content-Type'])
print (status )
print (content)


