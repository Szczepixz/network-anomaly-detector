# Network Anomaly Detector

A simple project for detecting unusual patterns in network traffic.

## About

This project works on network flow data stored in a CSV file.
The current version can:
- load flow records from a CSV file,
- calculate basic traffic statistics,
- assign a simple anomaly score to each flow,
- show suspicious records based on a chosen threshold,
- save suspicious records to a CSV file.

## How It Works

Each flow has a few basic features, for example:
- protocol,
- source and destination ports,
- duration,
- bytes sent and received,
- packet count,
- failed logins.

The program calculates average values and standard deviation for the dataset.
Then it gives points to flows that stand out from the rest.

Right now the score is based on:
- duration,
- bytes sent,
- bytes received,
- packet count,
- failed logins.

If the final score is greater than or equal to the selected threshold, the flow is treated as suspicious.

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
python main.py --input data/demo_flows.csv
```

Run with a custom threshold:

```bash
python main.py --input data/demo_flows.csv --threshold 6.5
```

Save suspicious flows to a CSV file:

```bash
python main.py --input data/demo_flows.csv --output output/suspicious_flows.csv
```

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Real Data

The project does not capture live traffic by itself yet.
It can convert a simple CSV export from tshark into the flow format used by the detector.

Example tshark export:

```bash
tshark -i 7 -c 30 -T fields -E header=y -E separator=, -E quote=d -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport > data/real_tshark_packets.csv
```

## Current Status

The project already includes:
- flow model,
- CSV loader,
- basic statistics,
- simple statistical anomaly scoring,
- CLI arguments,
- tshark CSV conversion,
- CSV export,
- basic tests.

More improvements can be added later, for example better scoring, more features, and cleaner output.
