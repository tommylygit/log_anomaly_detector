"""Log parser and feature builder for the anomaly detector.

Reads the raw web server log into a pandas DataFrame, then builds behavioral
features per IP (scans, brute force) and per 10-second window (DDoS).

Expected line format (produced by log_generator.py):
    IP - - [DD/Mon/YYYY:HH:MM:SS] "METHOD /path HTTP/1.1" STATUS
"""
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_score, recall_score

LOG_FILE = "server_log"
LABEL_FILE = "server_log_labels.csv"
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S"
WINDOW = "10s"
MIN_REQUESTS = 10            # judge an IP only if it has enough history
IP_CONTAMINATION = "auto"    # let the model decide how many IPs to flag
WINDOW_CONTAMINATION = 0.005 # alert budget: about 0.5 % of the windows


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


def true_ip_attackers(df):
    return df.groupby("ip")["label"].apply(lambda s: s.isin(["scan", "bruteforce"]).any())


def true_ddos_windows(df):
    return df.groupby("window")["label"].apply(lambda s: (s == "ddos").any())


def detect(features, contamination):
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=42)
    model.fit(features)
    flagged = pd.Series(model.predict(features) == -1, index=features.index)
    score = pd.Series(-model.score_samples(features), index=features.index)  # higher = more abnormal
    return flagged, score


def report(name, y_true, flagged, score):
    print(f"{name}: {flagged.sum()} alerts out of {len(flagged)} rows")
    print(f"  precision = {precision_score(y_true, flagged):.3f}")
    print(f"  recall    = {recall_score(y_true, flagged):.3f}")
    print(f"  average precision (any threshold) = {average_precision_score(y_true, score):.3f}")


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

    # Scans and brute force: one verdict per IP (IPs with too little history are skipped)
    ip_features = ip_features[ip_features["n_requests"] >= MIN_REQUESTS]
    ip_flagged, ip_score = detect(ip_features, IP_CONTAMINATION)
    ip_true = true_ip_attackers(df).loc[ip_features.index]
    report("Per IP (scan, brute force)", ip_true, ip_flagged, ip_score)

    # DDoS: one verdict per 10-second window
    win_flagged, win_score = detect(window_features, WINDOW_CONTAMINATION)
    win_true = true_ddos_windows(df).loc[window_features.index]
    report("Per window (DDoS)", win_true, win_flagged, win_score)


if __name__ == "__main__":
    main()
