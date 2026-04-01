# Network Anomaly Detector

A simple project for detecting unusual patterns in network traffic.

## About

This project works on network flow data stored in a CSV file.
The current version can:
- load flow records from a CSV file,
- calculate basic traffic statistics,
- assign a simple anomaly score to each flow,
- show suspicious records based on a chosen threshold.

## How It Works

Each flow has a few basic features, for example:
- protocol,
- duration,
- bytes sent and received,
- packet count,
- failed logins.

The program calculates average values and standard deviation for the dataset.
Then it gives points to flows that stand out from the rest.

Right now the score is based on:
- duration,
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

## Running Tests

```bash
python -m unittest discover -s tests -v
```

## Current Status

The project already includes:
- flow model,
- CSV loader,
- basic statistics,
- simple statistical anomaly scoring,
- CLI arguments,
- basic tests.

More improvements can be added later, for example better scoring, more features, and cleaner output.
