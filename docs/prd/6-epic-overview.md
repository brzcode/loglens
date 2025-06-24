# 6. Epic Overview

**Epic 1: Core Analysis Engine & CLI**
**Goal:** To build the foundational, functioning command-line tool that can ingest a single log file, parse it, apply basic detection patterns, and output a raw list of findings. This epic delivers the core processing capability.

* Story 1.1: Project Scaffolding & CLI Entry Point
* Story 1.2: Log File Ingestion
* Story 1.3: Implement Apache Log Parser
* Story 1.4: Basic Keyword-Based Detection

**Epic 2: IP Reputation & Report Refinement**
**Goal:** To enhance the core tool by adding external IP reputation context to the findings and refining the final output into a clear, prioritized summary report for the analyst. This epic delivers the "intelligence" layer.

* Story 2.1: Integrate IP Reputation Service
* Story 2.2: Implement Additional Detection Logic (Frequency)
* Story 2.3: Format and Prioritize the Final Report
