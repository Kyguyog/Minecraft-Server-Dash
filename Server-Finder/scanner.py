import socket
import time
import json
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from mcstatus import JavaServer
from tqdm import tqdm

# Ask user for the network block (Defaults to 104.193.0.0/16 if you just press Enter)
user_input = input("Enter network block (e.g., 104.193.0.0/16 or 45.63.0.0/16) [Default: 104.193.0.0/16]: ").strip()
target_network = user_input if user_input else "104.193.0.0/16"

try:
    net = ipaddress.ip_network(target_network, strict=False)
except ValueError as e:
    print(f"Invalid network format: {e}")
    exit()

print(f"\n[SCALABLE SCANNER] Loading network: {target_network}")
print("Generating host IPs (this might take a second for large ranges)...")

all_ips = list(net.hosts())
total_ips = len(all_ips)
print(f"Total IPs queued for scanning: {total_ips:,}\n")

found_servers = []
output_file = "found_servers.json"

def check_ip(ip):
    address = f"{ip}:25565"
    try:
        # Fast 0.4s timeout to keep large scans moving quickly
        server = JavaServer.lookup(address, timeout=0.4)
        status = server.status()
        return {
            "ip": str(ip),
            "address": address,
            "version": status.version.name,
            "motd": str(status.description),
            "online": status.players.online,
            "max": status.players.max
        }
    except Exception:
        return None

# High thread count (100 workers) to power through thousands of IPs fast
max_workers = 100

start_time = time.time()

with ThreadPoolExecutor(max_workers=max_workers) as executor:
    future_to_ip = {executor.submit(check_ip, ip): ip for ip in all_ips}
    
    with tqdm(total=total_ips, desc="Scanning Progress", unit="ip") as pbar:
        for future in as_completed(future_to_ip):
            result = future.result()
            pbar.update(1)
            
            if result:
                tqdm.write(f"\n >>> [SERVER FOUND!] {result['address']}")
                tqdm.write(f"     Version: {result['version']}")
                tqdm.write(f"     MOTD: {result['motd']}")
                tqdm.write(f"     Players: {result['online']}/{result['max']}\n")
                
                found_servers.append(result)

elapsed = time.time() - start_time

# Save results to JSON for your dashboard
if found_servers:
    # Load existing if file exists so you don't overwrite previous scans
    existing_data = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                existing_data = json.load(f)
        except Exception:
            pass
            
    # Combine and deduplicate by IP address
    existing_ips = {s['ip'] for s in existing_data}
    new_adds = [s for s in found_servers if s['ip'] not in existing_ips]
    combined = existing_data + new_adds
    
    with open(output_file, "w") as f:
        json.dump(combined, f, indent=4)
    print(f"\nSaved {len(new_adds)} new servers to '{output_file}'!")

print(f"\nScan finished! Checked {total_ips:,} IPs in {elapsed:.2f} seconds.")
print(f"Total active Minecraft servers found in this batch: {len(found_servers)}")