# Microsoft Sentinel Security Content

A practical collection of Microsoft Sentinel analytics rules, KQL detections, deployment-ready JSON files, and validation resources for security teams working with Microsoft Sentinel.

This repository is intended to help security analysts, engineers, architects, and Microsoft Sentinel practitioners accelerate the development, deployment, and testing of security monitoring use cases.

## Overview

Building effective detections in Microsoft Sentinel often requires more than writing a KQL query. A detection must also be packaged correctly, mapped to the relevant entities, configured with an appropriate schedule, and tested against representative activity.

This repository brings those components together in a reusable format.

The content includes Microsoft Sentinel analytics rules and supporting resources designed to help practitioners:

- Understand the security scenario addressed by each detection
- Review and customise the underlying KQL
- Deploy analytics rules into Microsoft Sentinel
- Generate or simulate relevant test activity where supporting commands are provided
- Validate whether the expected logs are being collected
- Use the content as a starting point for customer demonstrations, workshops, lab testing, or production engineering

## Repository Objectives

The project aims to make Microsoft Sentinel detection engineering more accessible and operational by providing examples that move beyond conceptual KQL.

Each use case may include one or more of the following:

- Microsoft Sentinel analytics rule definitions
- KQL detection logic
- JSON deployment files
- Required tables or log sources
- Example test commands
- Suggested validation steps
- Investigation context
- Relevant MITRE ATT&CK mappings

The repository is designed as a learning and implementation resource. The detection content should be reviewed and adapted to match the logging configuration, security requirements, and operational processes of each environment.

## What You Can Use This Repository For

### Detection Engineering

Use the analytics rules and KQL queries as starting points for developing detections that address your organisation’s monitoring requirements.

### Microsoft Sentinel Deployment

Where deployment-ready JSON files are provided, they can be imported or adapted for deployment into a Microsoft Sentinel workspace.

### Detection Validation

Some use cases include example commands that can help generate representative activity. These can be used in an authorised lab environment to determine whether:

1. The expected audit event is generated
2. The event is ingested into the required Microsoft Sentinel table
3. The KQL query returns the expected result
4. The analytics rule creates an alert or incident as configured

### Workshops and Demonstrations

The repository can support:

- Microsoft Sentinel workshops
- Security operations demonstrations
- Detection engineering exercises
- Proof-of-concept activities
- Analyst training
- Customer onboarding
- Lab-based validation

### Learning KQL

The queries can also be used to study practical KQL techniques such as:

- Filtering security events
- Parsing structured and unstructured data
- Extracting relevant fields
- Aggregating activity
- Correlating events
- Applying thresholds
- Mapping query results to Microsoft Sentinel entities

## Typical Use Case Structure

Content may differ between folders, but a detection use case will generally contain the following components:

```text
Use-Case-Name/
├── README.md
├── AnalyticsRule.json
├── DetectionQuery.kql
└── TestCommands.sql
