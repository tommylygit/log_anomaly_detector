"""
Produces two files:
  - server_log             : one request per line
                             IP - - [DD/Mon/YYYY:HH:MM:SS] "METHOD /path HTTP/1.1" STATUS
  - server_log_labels.csv  : the label of each line (normal, ddos, scan, bruteforce)
    -> used only to evaluate the detector, never as an input feature of the model.
"""

import random as rd
from datetime import datetime, timedelta


SEED = 42
N_REQUESTS = 100000
START = datetime(2026, 10, 7, 0, 0, 0)
MEAN_GAP = 0.8 # average seconds between two normal requests
N_CLIENTS = 300


P_DDOS = 0.0002
P_SCAN = 0.0005
P_BRUTE = 0.0005


DDOS_LINES = 60
DDOS_BOTS = 20
DDOS_GAP = 0.03
SCAN_LINES = 20
SCAN_GAP = 0.4
BRUTE_LINES = 40
BRUTE_GAP = 0.6

LOG_FILE = "server_log"
LABEL_FILE = "server_log_labels.csv"


methods = ["GET", "POST", "DELETE"]
method_weights = [0.80, 0.17, 0.03]

paths = ["/", "/login", "/api/data", "/assets/style.css"]
path_weights = [0.35, 0.15, 0.30, 0.20]

status_codes = ["200", "404", "500", "401"] # 200 ok, 404 not found, 500 server error, 401 unauthorized
status_weights = [0.91, 0.06, 0.02, 0.01]

sensitive_paths = ["/admin.php", "/backup.zip", "/.env", "/config.yaml"]


def generate_ip():
    part1 = rd.randint(0, 255)
    part2 = rd.randint(0, 255)
    part3 = rd.randint(0, 255)
    part4 = rd.randint(0, 255)
    return f"{part1}.{part2}.{part3}.{part4}"


def generate_attacker_ip(clients):
    ip = generate_ip()
    while ip in clients:
        ip = generate_ip()
    return ip


def generate_timestamp(t):
    date = START + timedelta(seconds=t)
    return date.strftime("%d/%b/%Y:%H:%M:%S")


def generate_log_line(ip, t, method, path, status):
    return f'{ip} - - [{generate_timestamp(t)}] "{method} {path} HTTP/1.1" {status}'


def generate_normal_request(clients, t):
    ip = rd.choice(clients)
    path = rd.choices(paths, weights=path_weights)[0]
    if path == "/assets/style.css":
        method = "GET"
    else:
        method = rd.choices(methods, weights=method_weights)[0]
    status = rd.choices(status_codes, weights=status_weights)[0]
    return generate_log_line(ip, t, method, path, status)


def ddos_attack(t0):
    bots = []
    for i in range(DDOS_BOTS):
        bots.append(generate_ip())

    events = []
    for i in range(DDOS_LINES):
        t = t0 + i * DDOS_GAP
        line = generate_log_line(rd.choice(bots), t, rd.choice(methods), rd.choice(paths), "500")
        events.append((t, line, "ddos"))
    return events


def scan_attack(t0, clients):
    scanner_ip = generate_attacker_ip(clients)

    events = []
    for i in range(SCAN_LINES):
        t = t0 + i * SCAN_GAP
        line = generate_log_line(scanner_ip, t, "GET", rd.choice(sensitive_paths), "404")
        events.append((t, line, "scan"))
    return events


def brute_force_attack(t0, clients):
    attacker_ip = generate_attacker_ip(clients)

    events = []
    for i in range(BRUTE_LINES):
        t = t0 + i * BRUTE_GAP
        line = generate_log_line(attacker_ip, t, "POST", "/login", "401")
        events.append((t, line, "bruteforce"))
    return events

#main function
def main():
    rd.seed(SEED)

    clients = []
    for i in range(N_CLIENTS):
        clients.append(generate_ip())


    events = []
    t = 0.0
    for i in range(N_REQUESTS):
        t += rd.expovariate(1 / MEAN_GAP) # random waiting time before the next request
        events.append((t, generate_normal_request(clients, t), "normal"))


        draw = rd.random()
        if draw < P_DDOS:
            events.extend(ddos_attack(t))
        elif draw < P_DDOS + P_SCAN:
            events.extend(scan_attack(t, clients))
        elif draw < P_DDOS + P_SCAN + P_BRUTE:
            events.extend(brute_force_attack(t, clients))

    events.sort() # sort by time so attacks are mixed with normal traffic

    with open(LOG_FILE, "w") as log, open(LABEL_FILE, "w") as labels:
        labels.write("line,label\n")
        line_number = 1
        for event in events:
            log.write(event[1] + "\n")
            labels.write(f"{line_number},{event[2]}\n")
            line_number += 1

    n_attacks = 0
    for event in events:
        if event[2] != "normal":
            n_attacks += 1
    print(f"{len(events)} lines written to {LOG_FILE} "
          f"({n_attacks} attack lines, {100 * n_attacks / len(events):.1f} %)")


if __name__ == "__main__":
    main()
