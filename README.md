# Log-based anomaly detection

A small end-to-end project: generate realistic web server logs with simulated attacks, turn the raw lines into behavioral features with pandas, and detect the attacks with an Isolation Forest (unsupervised). The labels produced by the generator are used **only to evaluate** the detector, never as a model input.

## Pipeline

```
log_generator.py  ->  server_log + server_log_labels.csv
anomaly_detector.py  ->  parse -> features -> Isolation Forest -> precision / recall
```

1. **Generate** (`log_generator.py`): a seeded generator writes an Apache-style access log and a separate label file (`normal`, `ddos`, `scan`, `bruteforce`, one label per line).
2. **Parse** (`anomaly_detector.py`): each line is split into IP, timestamp, method, path and status, and loaded into a pandas DataFrame.
3. **Build features**: behavior per IP (scans, brute force) and per 10-second window (DDoS).
4. **Detect**: one Isolation Forest per feature table.
5. **Evaluate**: alerts are compared with the true labels (precision, recall, average precision).

## Simulated traffic

With the default seed (42) one run produces **103,800 lines**, of which **3,800 (3.7 %) are attacks**.

| Part | Description |
|---|---|
| Normal traffic | 100,000 requests from 300 regular client IPs; random gaps between requests (exponential, mean 0.8 s); weighted choice of method, path and status (about 91 % `200`, 6 % `404`, 2 % `500`, 1 % `401`) |
| DDoS | burst of 60 lines of `500` errors from 20 different IPs within about 2 seconds (20 bursts in the default run) |
| Scan | one IP requests sensitive paths (`/.env`, `/admin.php`, ...) and gets `404` (20 lines, 44 scans in the default run) |
| Brute force | one IP chains rejected `POST /login` attempts, all `401` (40 lines, 43 attacks in the default run) |

Line format: `IP - - [DD/Mon/YYYY:HH:MM:SS] "METHOD /path HTTP/1.1" STATUS`. A single function writes every line, so attack lines and normal lines have exactly the same format and the model cannot learn from formatting.

## Features

- **Per IP** (whole log): number of requests, number of distinct paths, error rate, share of `404`, share of `401`. Targets scans and brute force. IPs with fewer than 10 requests are not judged (too little history).
- **Per 10-second window**: number of requests, number of distinct IPs, error rate, share of `500`. Targets DDoS, which uses many IPs, so it cannot be seen per IP.

## Model and evaluation

`sklearn.ensemble.IsolationForest` (200 trees, `random_state=42`). The model flags the rows that are the easiest to isolate. Truth for evaluation: an IP is an attacker if it sent a scan or a brute force; a window is a DDoS window if it contains DDoS lines.

Results with the default seed:

| Detector | Rows judged | True attacks | Alerts | Precision | Recall | Average precision |
|---|---|---|---|---|---|---|
| Per IP (scan, brute force) | 388 IPs | 87 | 106 | 0.821 | 1.000 | 0.967 |
| Per window (DDoS) | 8,012 windows | 25 | 41 | 0.610 | 1.000 | 0.998 |

*Average precision* is computed from the model scores and does not depend on any alert threshold.

Reading the false alerts:
- **Per IP**: 19 false alerts, mostly regular clients at the edge of the normal range (slightly more errors than average) and one DDoS bot IP that appeared 10 times.
- **Per window**: 16 false alerts, 10 of which are windows containing a scan or a brute force (real attacks, but not DDoS), the others being small windows with a few errors.

## Limitations

- **Synthetic data.** The attacks are clearly different from normal traffic by construction, so a recall of 1.0 does not mean the method would work as well on real logs.
- **One dataset.** The results come from a single run (seed 42); other seeds were not tested yet.
- **Alert budget.** For the per-window detector the expected share of alerts (`WINDOW_CONTAMINATION = 0.005`) is set by hand, with a rough idea of how rare attacks are. Average precision is reported because it does not depend on this choice.
- **No train/test split.** The Isolation Forest is unsupervised and is evaluated on the same data it was fitted on.
- **Minimum history.** The per-IP detector ignores IPs with fewer than 10 requests, so it would not catch an attacker that stays below this.

## Possible next steps

- Load the DataFrame into **SQLite** and rebuild the same per-IP and per-window features with SQL queries (`GROUP BY`), to compare with the pandas version.
- **Repeat the evaluation on several seeds** and report the mean and spread of the scores.

## Run it

```bash
pip install -r requirements.txt    # pandas, scikit-learn
python log_generator.py            # writes server_log and server_log_labels.csv
python anomaly_detector.py         # parses, builds features, detects, prints the metrics
```

`server_log` and `server_log_labels.csv` are generated files and are ignored by Git.
