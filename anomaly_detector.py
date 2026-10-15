"""Log parser: turns the raw web server log into a pandas DataFrame.

Expected line format (produced by log_generator.py):
    IP - - [DD/Mon/YYYY:HH:MM:SS] "METHOD /path HTTP/1.1" STATUS
"""
import pandas as pd

LOG_FILE = "server_log"
LABEL_FILE = "server_log_labels.csv"
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S"


def parse_line(line):
    parts = line.strip().split('"')
    date = parts[0].split("[")[1].split("]")[0]
    method, path, _ = parts[1].split()
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

#main
def main():
    df = load_logs()
    df["label"] = load_labels().values

    print(df.shape)
    print(df.dtypes)
    print(df.head())
    print(df["label"].value_counts())


if __name__ == "__main__":
    main()















