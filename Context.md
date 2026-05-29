# MiniSOAR Program Flow

This document explains the current MiniSOAR runtime flow based on the project architecture:

`Logstash -> Redis -> Python Script -> Telegram`

## High-Level Graph

```mermaid
flowchart LR
    A[Security Device / Raw Logs]
    B[Logstash]
    C[Redis Queue / Channel]
    D[Python Alert Worker]
    E[Alert Enrichment]
    F[Telegram Bot / Chat]

    A --> B
    B -->|parse, normalize, classify| C
    C -->|event payload| D
    D -->|lookup event details| E
    E -->|formatted alert message| F
```

## Runtime Flow

```mermaid
flowchart TD
    A[Incoming log event] --> B[Logstash analyzes log]
    B --> C[Field extraction and normalization]
    C --> D[Detection result written to Redis]
    D --> E[Python script reads Redis event]
    E --> F[Python validates config and payload]
    F --> G[Python enriches event context]
    G --> H[Build alert / summary message]
    H --> I[Send message to Telegram]
    I --> J[Analyst reviews alert]
```

## Script Responsibility

### 1. Logstash
- Receives raw logs from the monitored source.
- Parses and normalizes fields.
- Detects or tags events that should become MiniSOAR alerts.
- Pushes the processed event into Redis for downstream handling.

### 2. Redis
- Acts as the handoff layer between ingestion and alerting.
- Stores the event temporarily so the Python worker can consume it.
- Decouples log analysis speed from Telegram delivery speed.

### 3. Python Script
- Reads alert events from Redis.
- Validates environment settings and event structure.
- Enriches the event with extra context when needed.
- Formats the final alert text for operational use.
- Sends the alert into Telegram.

### 4. Telegram
- Becomes the analyst-facing notification channel.
- Receives the formatted alert from the Python script.
- Allows operators to review the event quickly and continue response actions.

## Current Architecture View

```mermaid
flowchart LR
    subgraph Ingestion
        A1[Log Source]
        A2[Logstash Pipeline]
    end

    subgraph Buffering
        B1[Redis]
    end

    subgraph Processing
        C1[Python Consumer]
        C2[Event Enrichment]
        C3[Message Formatter]
    end

    subgraph Notification
        D1[Telegram Chat]
    end

    A1 --> A2
    A2 --> B1
    B1 --> C1
    C1 --> C2
    C2 --> C3
    C3 --> D1
```

## Short Summary

MiniSOAR currently works as an alert delivery pipeline. Logstash analyzes incoming logs and pushes selected events into Redis. The Python layer consumes those Redis events, enriches and formats them, then sends the result to Telegram for analyst visibility.
