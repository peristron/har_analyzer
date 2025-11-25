# 🕵️‍♂️ HAR File Analyzer

A Streamlit application to analyze HTTP Archive (.har) files. This tool helps you debug network traffic, API calls, and specific platform interactions (like Okta, Google, etc.) without needing to install complex desktop software.

**[View Live Demo](#)** *(Add your Streamlit Cloud link here after deployment)*

## ✨ Features

*   **Keyword Filtering:** Automatically filter traffic by domain or header keywords (default: "okta", but configurable).
*   **Method Filtering:** Focus only on specific HTTP methods (POST, GET, etc.).
*   **Syntax Validation:** Detects and reports if a HAR file is truncated or corrupt (common with browser downloads).
*   **Interactive Table:** Sortable traffic log with color-coded status codes.
*   **Deep Inspection:** View Headers, Bodies (JSON/Text), and Cookies for both Requests and Responses.

## 🚀 How to use

1.  Export a `.har` file from your browser's Developer Tools (Network Tab).
2.  Upload the file to the analyzer.
3.  Use the sidebar to filter for specific terms (e.g., `api/v1/users` or `error`).
4.  Click on a specific row in the table to inspect the JSON payloads.

## 🔒 Privacy Note

This application processes data **in-memory**. Your uploaded HAR file is processed by the server and discarded immediately after the session. No data is permanently stored. 

**However**, HAR files can contain sensitive data such as:
*   Session Cookies
*   Bearer Tokens
*   PII (Personally Identifiable Information)

Please sanitize your HAR files before uploading if they contain highly sensitive production credentials.

## 🛠️ Running Locally

To run this application on your own machine:

1.  Clone this repository.
2.  Install requirements:
    ```bash
    pip install -r requirements.txt
    ```
3.  Run the app:
    ```bash
    streamlit run har_analyzer.py
    ```
