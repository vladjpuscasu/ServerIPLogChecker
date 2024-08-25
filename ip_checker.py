# The following module takes a server log file and parses IP's with more than 100 hits # 
# It runs them through the AbuseIPDB API to check their locations and sorts them by highest abuseConfidenceScore
# You will need abuseIPDB api key *free* as well as have Python installed, you will need to have Requests installed - pip install requests  #

import requests
from collections import Counter

def parse_log_file(log_file_path):
    ip_addresses = []
    
    with open(log_file_path, 'r') as file:
        for line in file:
            ip = line.split()[0]
            ip_addresses.append(ip)
    
    return ip_addresses

def count_ips(ip_addresses):
    return Counter(ip_addresses)

def fetch_abuse_info(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, params={'ipAddress': ip})
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        result = response.json()
        abuse_confidence_score = result.get("data", {}).get("abuseConfidenceScore", 0)
        return abuse_confidence_score
    except requests.RequestException as e:
        print(f"Error fetching data for IP {ip}: {e}")
        return None

def check_ips_with_abuseipdb(ip_counts, api_key, output_query_file_path):
    ip_abuse_scores = []
    
    for ip, count in ip_counts.items():
        if count > 100:  #Change the threshold for IP hits 
            abuse_confidence_score = fetch_abuse_info(ip, api_key)
            if abuse_confidence_score is not None:
                ip_abuse_scores.append((ip, count, abuse_confidence_score))
    
    if not ip_abuse_scores:
        print("No IPs with more than 100 hits or no valid abuse confidence scores found.")
    
    # Sort IPs by abuse confidence score in descending order
    sorted_ip_abuse_scores = sorted(ip_abuse_scores, key=lambda x: x[2], reverse=True)
    
    with open(output_query_file_path, 'w') as file:
        file.write("IP Address\t\tHits\t\tAbuse Confidence Score\n")
        file.write("-" * 80 + "\n")
        
        for ip, count, score in sorted_ip_abuse_scores:
            file.write(f"{ip}\t\t{count}\t\t{score}\n")

def main():
    log_file_path = 'log.log'  # Replace with your log file name
    output_file_path = 'ip_query_results.txt'  # File for storing query results
    api_key = "1d36419a6a8263560e6d6aadfa6226376ba377249a4e6bf8eef3ac0f501ebf746891acf56a0d1e3e"  # Replace with your AbuseIPDB API key
    
    ip_addresses = parse_log_file(log_file_path)
    ip_counts = count_ips(ip_addresses)
    
    check_ips_with_abuseipdb(ip_counts, api_key, output_file_path)

if __name__ == "__main__":
    main()
