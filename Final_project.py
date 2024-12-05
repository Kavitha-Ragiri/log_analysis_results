
import re
import csv
from collections import Counter

def analyze_logs(log_file_path, threshold=1):
    # Regular expressions
    ip_regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    endpoint_regex = r'\"(?:GET|POST|PUT|DELETE|PATCH) (\S+) HTTP\/'
    failure_regex = r'401|Invalid credentials'

    # Counters
    requests_per_ip = Counter()
    endpoint_count = Counter()
    failed_attempts = Counter()

    # Read the log file
    with open(log_file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_match = re.search(ip_regex, line)
            if ip_match:
                ip = ip_match.group()
                requests_per_ip[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(endpoint_regex, line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_count[endpoint] += 1

            # Detect failed login attempts
            if re.search(failure_regex, line) and ip_match:
                failed_attempts[ip] += 1

    # Most accessed endpoint
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1], default=("None", 0))

    # Suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}

    # Output results
    print("\nRequests Per IP:")
    print(f"{'IP Address'} {'Request Count'}")
    for ip, count in requests_per_ip.items():
        print(f"{ip}: {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip}: {count}")
    else:
        print("No suspicious activity detected.")

    # Saving results to CSV
    with open("log_analysis_results.csv", 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # requests per IP
        writer.writerow(["Requests Per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in requests_per_ip.items():
            writer.writerow([ip, count])

        # most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

    print("\nResults saved to log_analysis_results.csv")

# function call
log_file_path = "C:/Users/Rajasekhar Ragiri/OneDrive/Desktop/console.log"
analyze_logs(log_file_path, threshold=1)
