# Network Anomaly Detector

A simple project for detecting unusual patterns in network traffic.

## About

This project works on network flow data stored in a CSV file.
The current version can:
- load flow records from a CSV file,
- calculate basic traffic statistics,
- assign a simple anomaly score to each flow,
- run Isolation Forest on flow features,
- run Local Outlier Factor on flow features,
- compare detection methods on the same dataset,
- show suspicious records with the selected method,
- save suspicious records to a CSV file.

## How It Works

Each flow has a few basic features, for example:
- protocol,
- local and remote ports,
- duration,
- bytes sent and received,
- packets sent and received,
- failed logins.

The program calculates average values and standard deviation for the dataset.
Then it gives points to flows that stand out from the rest.

There are now three analysis methods:
- `statistical` for the current z-score based scoring,
- `isolation-forest` for a simple ML-based anomaly detector,
- `local-outlier-factor` for a second ML-based anomaly detector.

It also calculates some simple extra features such as:
- total bytes,
- total packets,
- bytes per second,
- packets per second,
- sent/received ratio.

Right now the score is based on:
- duration,
- bytes sent,
- bytes received,
- total bytes,
- packet count,
- bytes per second,
- packets per second,
- sent/received ratio,
- failed logins.

If the final score is greater than or equal to the selected threshold, the flow is treated as suspicious.
With Isolation Forest, the model marks the flows it considers unusual.

## Project Structure

```text
network-anomaly-detector/
|- data/
|- src/
`- tests/
```

## Running The Project

Run the demo dataset:

```bash
python main.py analyze --input data/demo_flows.csv
```

Run with a custom threshold:

```bash
python main.py analyze --input data/demo_flows.csv --threshold 6.5
```

Run the ML-based mode:

```bash
python main.py analyze --input data/demo_flows.csv --method isolation-forest --contamination 0.2
```

Run the second ML-based mode:

```bash
python main.py analyze --input data/demo_flows.csv --method local-outlier-factor --contamination 0.2
```

Compare all methods on the same file:

```bash
python main.py compare-methods --input data/demo_flows.csv --threshold 4 --contamination 0.2
```

Save suspicious flows to a CSV file:

```bash
python main.py analyze --input data/demo_flows.csv --output output/suspicious_flows.csv
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Install

If you want to use Isolation Forest:

```bash
pip install -r requirements.txt
```

## Real Data

The project can capture a small packet sample with tshark and convert it into the flow format used by the detector.

List available interfaces:

```bash
python main.py list-interfaces
```

Quick scan:

```bash
python main.py scan-tshark --interface 7 --local-ip 192.168.33.16 --count 50 --threshold 2 --cleanup
```

Quick scan with Isolation Forest:

```bash
python main.py scan-tshark --interface 7 --local-ip 192.168.33.16 --count 50 --method isolation-forest --contamination 0.2 --cleanup
```

Quick scan with Local Outlier Factor:

```bash
python main.py scan-tshark --interface 7 --local-ip 192.168.33.16 --count 50 --method local-outlier-factor --contamination 0.2 --cleanup
```

By default, scan files are saved with a timestamp, so older scans are not overwritten.
Use `--cleanup` if you do not want to keep the packet and flow CSV files after the scan.

The interface number can be different on another machine. If `tshark` is not in PATH, add `--tshark-path`.

You can also run the steps separately.

1. Capture a small CSV sample:

```bash
python main.py capture-tshark --interface 7 --count 50 --output data/real_tshark_packets.csv
```

2. Convert the tshark CSV to flow CSV:

```bash
python main.py convert-tshark --input data/real_tshark_packets.csv --output output/real_flows.csv --local-ip 192.168.33.16
```

3. Analyze the converted file:

```bash
python main.py analyze --input output/real_flows.csv --threshold 2
```

## Results

I tested the project on a bigger real traffic sample captured with `tshark`.

- `5000` packets were captured
- they were converted into `130` flows
- `statistical` detected `22` suspicious flows
- `isolation-forest` detected `26`
- `local-outlier-factor` also detected `26`

The most interesting part was the overlap between methods.
`8` flows were detected by all three methods, so they can be treated as the strongest anomaly candidates in that sample.

The methods did not always agree on everything.
It shows that each method looks at the data a bit differently.
The statistical method focused more on strong feature differences, while the ML-based methods also caught flows that looked unusual in a less obvious way.

## Current Status

The project already includes:
- flow model,
- CSV loader,
- basic statistics,
- simple statistical anomaly scoring,
- Isolation Forest support,
- Local Outlier Factor support,
- method comparison mode,
- CLI arguments,
- tshark capture,
- tshark CSV conversion,
- local-ip based bidirectional flows,
- one-command tshark scan,
- CSV export,
- basic tests.

More improvements can be added later, for example better scoring, more features, and cleaner output.
