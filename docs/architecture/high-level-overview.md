# High-Level Overview

The architectural style is a **Monolith**, as the entire functionality is packaged into a single, cohesive CLI application. The repository structure will be a **Monorepo**.

The primary user interaction flow is simple:

1.  The L1 SOC Analyst invokes the tool via their terminal, providing a path to a log file.
2.  LogLens processes the file internally, making external calls only to an IP reputation API for data enrichment.
3.  A formatted summary of findings is printed directly to the analyst's console.

<!-- end list -->

```mermaid
graph TD
    subgraph Local Machine
        User(L1 SOC Analyst) -- Invokes --> CLI(LogLens CLI)
        CLI -- Reads --> LogFile(log_file.log)
        CLI -- Generates --> Report(Console Output)
    end
    CLI -- HTTPS Request --> IPReputationAPI(IP Reputation API)
```
