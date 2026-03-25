# Network Anomaly Detector

A simple project for detecting unusual patterns in network traffic.

## About

The goal of this repository is to build a basic anomaly detector for network flow data.

For the first version, I want to keep it simple and focus on:
- loading flow records from a CSV file,
- analyzing selected traffic features,
- marking records that differ from normal behavior.

## First Version Plan

The first version should:
- read network flow data from a CSV file,
- compute a simple anomaly score,
- print suspicious records in a readable way.

## Planned Structure

```text
network-anomaly-detector/
|- data/
|- src/
`- tests/
```

## Status

Initial setup only. The implementation will be added step by step.