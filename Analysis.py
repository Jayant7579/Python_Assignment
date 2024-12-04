import re
import csv
import argparse
from collections import defaultdict
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_count = defaultdict(int)
    for log in logs:
        ip_address = log.split()[0]
        ip_count[ip_address] += 1
    return ip_count

def identify_most_accessed_endpoint(logs):
    endpoint_count = defaultdict(int)
    for log in logs:
        match = re.search(r'\"(GET|POST) (.+?) ', log)
        if match:
            endpoint = match.group(2)
            endpoint_count[endpoint] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=(None, 0))
    return most_accessed, endpoint_count

def detect_suspicious_activity(logs):
    failed_login_count = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            ip_address = log.split()[0]
            failed_login_count[ip_address] += 1
    suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def save_results_to_csv(ip_counts, most_accessed, suspicious_ips, endpoint_count, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow([most_accessed[0], most_accessed[1]])
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in sorted(endpoint_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([endpoint, count])

def main():
    parser = argparse.ArgumentParser(description='Analyze log files for IP requests, endpoints, and suspicious activity.')
    parser.add_argument('log_file', type=str, help='Path to the log file to analyze')
    parser.add_argument('--top_ips', type=int, default=5, help='Number of top IP addresses to display')
    parser.add_argument('--top_endpoints', type=int, default=5, help='Number of top endpoints to display')
    parser.add_argument('--output_file', type=str, default='log_analysis_results.csv', help='Output CSV file name')
    
    args = parser.parse_args()
    logs = parse_log_file(args.log_file)
    
    ip_counts = count_requests_per_ip(logs)
    most_accessed, endpoint_count = identify_most_accessed_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)
    print("IP Address Request Count")
    
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:args.top_ips]:
        print(f"{ip:<20} {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    print("\nSuspicious Activity Detected:")
    print("IP Address Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    print("\nTop Endpoints Accessed:")
    print("Endpoint Access Count")

    for endpoint, count in sorted(endpoint_count.items(), key=lambda x: x[1], reverse=True)[:args.top_endpoints]:
        print(f"{endpoint:<20} {count}")

    save_results_to_csv(ip_counts, most_accessed, suspicious_ips, endpoint_count, args.output_file)
    print(f"\nResults saved to {args.output_file}")

if __name__ == "__main__":
    main()