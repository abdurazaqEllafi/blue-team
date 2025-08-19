import os , time 
import requests 
BASE = "https://httpbin.org" 


with requests.session() as s : 
    for i in range(3): 
        r = s.get(f"{BASE}/user-agent", timeout=5)
        x = s.get(f"{BASE}/ip")
        if r.status_code == 200 and x.status_code == 200 : 
            break 

print(r.status_code)        
print(r.json())
print(x.json())  