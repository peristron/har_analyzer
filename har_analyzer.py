# PREPPING for public deployment; to deal with sensitive SessionId portion of the workflow; this is "V3" as deployed to Github as of 11.24.2025 11:25PM
# run command:
#   streamlit run har_analyzer.py
# verify dependencies are installed - pip install streamlit requests pandas beautifulsoup4 playwright   THEN   python -m playwright install (shouldn't need to do this)
# directory setup:
#   cd c:\users\oakhtar\documents\pyprojs_local  (replace name/path if needed)
#!/usr/bin/env python3
# -- coding: utf-8 --

import streamlit as st
import json
import pandas as pd
from urllib.parse import urlparse

# --- Page Configuration ---
st.set_page_config(
    page_title="HAR File Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CSS for better visual separation ---
st.markdown("""
<style>
    div[data-testid="stMetricValue"] { font-size: 24px; }
    .warning-box { background-color: #fff3cd; padding: 10px; border-radius: 5px; border: 1px solid #ffeeba; color: #856404; }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---

@st.cache_data(show_spinner=False)
def load_har_data(file_content):
    """
    Parses JSON content. Cached to prevent re-parsing on every interaction.
    """
    return json.loads(file_content)

def validate_har(data):
    """Checks if the JSON has the basic HAR structure."""
    if 'log' not in data:
        return False, "Missing 'log' key. This does not appear to be a valid HAR file."
    if 'entries' not in data['log']:
        return False, "Missing 'log.entries'. The file structure is incomplete."
    return True, ""

def filter_traffic(har_data, keyword, selected_methods):
    entries = har_data.get('log', {}).get('entries', [])
    matches = []

    for entry in entries:
        request = entry.get('request', {})
        response = entry.get('response', {})
        
        url = request.get('url', '')
        method = request.get('method', '')
        status = response.get('status', 0)
        headers = request.get('headers', [])
        
        # --- Filter Logic ---
        
        # 1. Check Method (if filters selected)
        if selected_methods and method not in selected_methods:
            continue

        # 2. Check Keyword (Search in URL or Headers)
        keyword_hit = False
        match_source = "None"
        
        if not keyword:
            # If search is empty, match everything
            keyword_hit = True
            match_source = "All"
        else:
            k_lower = keyword.lower()
            # Search URL
            if k_lower in url.lower():
                keyword_hit = True
                match_source = "URL"
            else:
                # Search Headers
                for h in headers:
                    if k_lower in h.get('name', '').lower() or k_lower in h.get('value', '').lower():
                        keyword_hit = True
                        match_source = f"Header ({h.get('name')})"
                        break
        
        if keyword_hit:
            parsed = urlparse(url)
            
            matches.append({
                "Time": entry.get('startedDateTime'),
                "Method": method,
                "Status": status,
                "Domain": parsed.netloc,
                "Path": parsed.path,
                "Match Source": match_source,
                "Full URL": url,
                "_raw_entry": entry
            })
            
    return matches

# --- Sidebar Controls ---
st.sidebar.title("🔍 Filter Controls")

st.sidebar.info("Use these filters to narrow down the specific API calls or errors you are looking for.")

# 1. Search Term
search_term = st.sidebar.text_input("Search Keyword", value="okta", help="Search in URLs and Headers. Clear to see all traffic.")

# 2. Method Filter
available_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
selected_methods = st.sidebar.multiselect("HTTP Methods", available_methods, default=None, help="Leave empty to include all methods")

# --- Main UI ---

st.title("🕵️‍♂️ HAR File Analyzer")

# Privacy Disclaimer
with st.expander("ℹ️ Privacy & Security Note", expanded=False):
    st.markdown("""
    **Security Notice:**  
    This tool processes your HAR file **in-memory**. The file is uploaded to the application server for processing and is discarded immediately after your session ends. 
    However, HAR files can contain sensitive data (cookies, session tokens, passwords).  
    *Please sanitize your HAR files before uploading if they contain production secrets.*
    """)

uploaded_file = st.file_uploader("Upload a .har file to begin", type=["har", "json"])

if uploaded_file is not None:
    try:
        # Read file content safely
        content = uploaded_file.read()
        
        # Parse JSON
        har_data = load_har_data(content)
        
        # Validate HAR structure
        is_valid, error_msg = validate_har(har_data)
        
        if not is_valid:
            st.error(f"⚠️ Error: {error_msg}")
        else:
            # Get list of entries based on filters
            filtered_data = filter_traffic(har_data, search_term, selected_methods)
            
            total_count = len(har_data.get('log', {}).get('entries', []))
            filtered_count = len(filtered_data)
            
            # --- Metrics ---
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Requests", total_count)
            c2.metric("Filtered Matches", filtered_count)
            
            error_count = len([x for x in filtered_data if x['Status'] >= 400])
            c3.metric("Errors (4xx/5xx)", error_count, delta_color="inverse")
            
            st.divider()

            if not filtered_data:
                st.warning(f"No requests found matching your filter: '{search_term}'")
            else:
                # --- Main Dataframe ---
                df = pd.DataFrame(filtered_data)
                
                # Styling the status column (updated for newer Pandas versions)
                def highlight_status(val):
                    color = '#28a745' if val < 300 else '#ffc107' if val < 400 else '#dc3545'
                    weight = 'bold' if val >= 400 else 'normal'
                    return f'color: {color}; font-weight: {weight}'

                st.subheader("Traffic Log")
                
                display_cols = ["Method", "Status", "Domain", "Path", "Match Source"]
                
                # Use 'map' instead of 'applymap' for future compatibility
                st.dataframe(
                    df[display_cols].style.map(highlight_status, subset=['Status']),
                    use_container_width=True,
                    height=400
                )

                # --- Deep Dive Inspector ---
                st.subheader("🔎 Request Inspector")
                
                # Create a readable label for the dropdown
                options = {i: f"[{row['Status']}] {row['Method']} - {row['Domain']}{row['Path']}" for i, row in df.iterrows()}
                
                selected_index = st.selectbox(
                    "Select a request to view headers and payloads:", 
                    options=options.keys(), 
                    format_func=lambda x: options[x]
                )

                # Retrieve raw entry
                raw = df.iloc[selected_index]["_raw_entry"]
                req = raw['request']
                res = raw['response']

                # Tabs for organization
                tab_req, tab_res, tab_cookies, tab_raw = st.tabs(["➡️ Request", "⬅️ Response", "🍪 Cookies", "📄 Raw JSON"])

                with tab_req:
                    st.text_input("Full URL", req['url'], disabled=True)
                    
                    col_h, col_b = st.columns([1, 1])
                    with col_h:
                        st.markdown("**Headers**")
                        st.json({h['name']: h['value'] for h in req.get('headers', [])}, expanded=False)
                    with col_b:
                        st.markdown("**Post Data / Body**")
                        if 'postData' in req:
                            txt = req['postData'].get('text', '')
                            try:
                                st.json(json.loads(txt))
                            except:
                                st.text_area("Body", txt, height=300)
                        else:
                            st.info("No Body Payload")

                with tab_res:
                    st.markdown(f"**Status:** {res['status']} {res['statusText']}")
                    
                    col_h, col_b = st.columns([1, 1])
                    with col_h:
                        st.markdown("**Headers**")
                        st.json({h['name']: h['value'] for h in res.get('headers', [])}, expanded=False)
                    with col_b:
                        st.markdown("**Response Content**")
                        content_text = res.get('content', {}).get('text', '')
                        if content_text:
                            try:
                                st.json(json.loads(content_text))
                            except:
                                st.text_area("Body", content_text[:5000], height=300) # Limit display size
                        else:
                            st.info("No Content")

                with tab_cookies:
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**Request Cookies**")
                        st.dataframe(pd.DataFrame(req.get('cookies', [])), use_container_width=True)
                    with c2:
                        st.markdown("**Response Cookies**")
                        st.dataframe(pd.DataFrame(res.get('cookies', [])), use_container_width=True)

                with tab_raw:
                    st.json(raw)

    except json.JSONDecodeError as e:
        st.error("❌ **Errors found when processing the HAR file**")
        st.markdown(f"""
        **Unable to process the HAR file.**  
        This usually means the file was cut off (truncated) during the download.
        
        **Details:** `{e.msg}` at Line {e.lineno}, Column {e.colno}
        """)
        
    except Exception as e:
        st.error(f"An unexpected error occurred: {e}")