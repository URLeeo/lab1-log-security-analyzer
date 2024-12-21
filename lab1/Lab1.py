import re
import json
import csv
import os

# Fayl və qovluq adları
log_file = "server_logs.txt"
results_dir = "results"
failed_logins_file = os.path.join(results_dir, "failed_logins.json")
threat_ips_file = os.path.join(results_dir, "threat_ips.json")
combined_security_file = os.path.join(results_dir, "combined_security_data.json")
log_analysis_txt = os.path.join(results_dir, "log_analysis.txt")
log_analysis_csv = os.path.join(results_dir, "log_analysis.csv")

# Təhdid IP-ləri
threat_ips = {
    "192.168.1.11": "Suspicious activity detected",
    "10.0.0.50": "Known malicious IP",
    "172.16.0.5": "Brute-force attack reported"
}

# Nəticə qovluğunu yaratmaq
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Log faylını oxumaq
with open(log_file, "r") as file:
    logs = file.readlines()

# Regex əsaslı məlumat çıxarışı
ip_pattern = r"(\d{1,3}(?:\.\d{1,3}){3})"  # IP ünvanları üçün
date_pattern = r"\[(.*?)\]"                # Tarix üçün
method_pattern = r"\"(GET|POST|PUT|DELETE|HEAD)"  # HTTP metodları üçün

failed_attempts = {}
log_entries = []

for log in logs:
    ip_match = re.search(ip_pattern, log)
    date_match = re.search(date_pattern, log)
    method_match = re.search(method_pattern, log)
    status_code = re.search(r" (\d{3}) ", log).group(1)

    if ip_match and date_match and method_match:
        ip = ip_match.group(1)
        date = date_match.group(1)
        method = method_match.group(1)
        log_entries.append((ip, date, method))

        # Uğursuz girişlərin sayını izləmək
        if status_code == "401":  # 401 kodu uğursuz giriş üçündür
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

# 5-dən çox uğursuz giriş edən IP-lər
high_risk_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}

# Nəticələri JSON formatında yazmaq
with open(failed_logins_file, "w") as file:
    json.dump(high_risk_ips, file, indent=4)

with open(threat_ips_file, "w") as file:
    json.dump(threat_ips, file, indent=4)

# Uğursuz giriş və təhdid məlumatlarını birləşdirmək
combined_data = {}
for ip, description in threat_ips.items():
    combined_data[ip] = {"description": description, "failed_attempts": failed_attempts.get(ip, 0)}

with open(combined_security_file, "w") as file:
    json.dump(combined_data, file, indent=4)

# TXT faylına yazmaq
with open(log_analysis_txt, "w") as file:
    for ip, count in failed_attempts.items():
        file.write(f"{ip}: {count} failed attempts\n")

# CSV faylına yazmaq
with open(log_analysis_csv, "w", newline="") as csvfile:
    csvwriter = csv.writer(csvfile)
    csvwriter.writerow(["IP Address", "Date", "HTTP Method", "Failed Attempts"])
    for ip, date, method in log_entries:
        csvwriter.writerow([ip, date, method, failed_attempts.get(ip, 0)])

print(f"Analiz tamamlandı! Nəticələr '{results_dir}' qovluğunda saxlanıldı.")
