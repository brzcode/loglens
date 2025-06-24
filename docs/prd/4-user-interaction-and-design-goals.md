# 4. User Interaction and Design Goals

**Overall Experience:** The interaction should be immediate and direct. The tool should feel like a fast, reliable utility that provides answers without unnecessary configuration or "chattiness." The experience should instill a sense of empowerment and clarity.

**Key Interaction Paradigm:**

* Command-Line Driven: All interaction will be through a terminal interface.
* Argument-Based Control: The user will control the analysis by providing simple arguments, primarily the parser type and the file path.
* Text as the UI: The "user interface" is the formatted text report printed to the console. It must be well-structured, using spacing and minimal symbols for maximum readability on a standard terminal screen.

**Conceptual "Views" / Outputs:**

* Default View (Summary Report): The standard output when running the tool is the prioritized summary report of the top 3-5 findings.
* Verbose View (Optional): A command-line flag (e.g., -v or --verbose) should be available to show more detailed information for each finding or to list a larger number of findings.
* Help View: A standard --help or -h flag must be implemented to display a clear, concise help message explaining the available commands, arguments, and flags.

**Target Platform:** The tool must function correctly and be readable in standard terminal environments, including bash, zsh, and PowerShell.
