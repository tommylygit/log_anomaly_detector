"""Log parser and feature builder for the anomaly detector.

Reads the raw web server log into a pandas DataFrame, then builds behavioral
features per IP (scans, brute force) and per 10-second window (DDoS).

Expected line format (produced by log_generator.py):
    IP - - [DD/Mon/YYYY:HH:MM:SS] "METHOD /path HTTP/1.1" STATUS
"""
import pandas as pd

LOG_FILE = "server_log"
LABEL_FILE = "server_log_labels.csv"
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S"
WINDOW = "10s"


def parse_line(line):
    parts = line.strip().split('"')            # 3 pieces: [ip and date] "request" status
    ip = parts[0].split()[0]
    date = parts[0].split("[")[1].split("]")[0]
    method, path, _ = parts[1].split()         # the protocol (HTTP/1.1) is ignored
    status = int(parts[2])
    return {"ip": ip, "timestamp": date, "method": method, "path": path, "status": status}


def load_logs(log_file=LOG_FILE):
    rows = []
    with open(log_file) as f:
        for line in f:
            rows.append(parse_line(line))

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format=DATE_FORMAT)
    return df


def load_labels(label_file=LABEL_FILE):
    return pd.read_csv(label_file)["label"]


def add_window(df):
    df["window"] = df["timestamp"].dt.floor(WINDOW)
    return df


def add_status_flags(df):
    df["is_error"] = df["status"] >= 400
    df["is_404"] = df["status"] == 404
    df["is_401"] = df["status"] == 401
    df["is_500"] = df["status"] == 500
    return df


def features_per_ip(df):
    return df.groupby("ip").agg(
        n_requests=("status", "size"),
        n_distinct_paths=("path", "nunique"),
        error_rate=("is_error", "mean"),
        share_404=("is_404", "mean"),
        share_401=("is_401", "mean"),
    )


def features_per_window(df):
    return df.groupby("window").agg(
        n_requests=("status", "size"),
        n_distinct_ips=("ip", "nunique"),
        error_rate=("is_error", "mean"),
        share_500=("is_500", "mean"),
    )


def main():
    df = load_logs()
    df["label"] = load_labels().values      # same order as the log lines
    df = add_status_flags(add_window(df))

    print(df.shape)
    print(df.head())
    print(df["label"].value_counts())

    ip_features = features_per_ip(df)
    window_features = features_per_window(df)
    print(ip_features.shape)
    print(ip_features.head())
    print(window_features.shape)
    print(window_features.head())


if __name__ == "__main__":
    main()















