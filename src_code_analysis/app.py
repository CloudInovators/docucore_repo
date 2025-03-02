import logging
import os
import streamlit as st
import subprocess
import pandas as pd
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
from pygments import highlight
from pygments.lexers import PythonLexer, JavaLexer, JavascriptLexer, CppLexer
from pygments.formatters import HtmlFormatter
from radon.complexity import cc_visit
from radon.metrics import mi_visit
import streamlit_ace as stace
import json
import re
import io
import contextlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the Databricks Workspace Client
w = WorkspaceClient()

# Extract only the endpoint name from the full URL
serving_endpoint = os.getenv("SERVING_ENDPOINT")
if serving_endpoint:
    serving_endpoint = serving_endpoint.split("/")[-1]  # Extract only the endpoint name
else:
    st.error("SERVING_ENDPOINT environment variable is not set.")

def calculate_code_metrics(code):
    """Calculate cyclomatic complexity and maintainability index."""
    complexity = cc_visit(code)
    maintainability = mi_visit(code, multi=True)  # Fixed: added multi=True argument
    return complexity, maintainability

def run_bandit(code):
    """Run Bandit for security vulnerability detection."""
    with open("temp_code.py", "w") as f:
        f.write(code)
    result = subprocess.run(["bandit", "-f", "json", "-o", "bandit_report.json", "temp_code.py"], capture_output=True, text=True)
    
    with open("bandit_report.json") as report_file:
        report_data = json.load(report_file)
    
    return report_data

def highlight_code(code, lang):
    """Highlight code snippets using Pygments."""
    lexers = {
        'python': PythonLexer(),
        'java': JavaLexer(),
        'javascript': JavascriptLexer(),
        'cpp': CppLexer()
    }
    
    lexer = lexers.get(lang, PythonLexer())  # Default to Python if lang not found
    formatter = HtmlFormatter()
    highlighted_code = highlight(code, lexer, formatter)
    
    return f'<style>{formatter.get_style_defs()}</style>{highlighted_code}'

def export_results(complexity_data, maintainability_data, security_report):
    """Export analysis results to a CSV file."""
    results = []

    # Add complexity data
    if complexity_data:
        for func in complexity_data:
            results.append({
                'Function Name': func.name,
                'Cyclomatic Complexity': func.complexity,
                'Maintainability Index': '',
                'Security Issues': ''
            })
    
    # Add maintainability index
    results.append({
        'Function Name': 'Overall',
        'Cyclomatic Complexity': '',
        'Maintainability Index': maintainability_data,
        'Security Issues': ''
    })
    
    # Add security report data
    if security_report['results']:
        for issue in security_report['results']:
            results.append({
                'Function Name': issue['filename'],
                'Cyclomatic Complexity': '',
                'Maintainability Index': '',
                'Security Issues': issue['issue_text'],
            })
    
    # Create DataFrame and export to CSV
    df = pd.DataFrame(results)
    df.to_csv('analysis_results.csv', index=False)

def split_code_into_snippets(code):
    """Split code into functions for separate analysis."""
    pattern = r'(?m)^def\s+\w+\(.*?\):'
    snippets = re.split(pattern, code)
    
    # Reattach function headers to their respective bodies
    snippets_with_headers = []
    function_defs = re.findall(pattern, code)
    
    for header, body in zip(function_defs, snippets[1:]):  # Skip the first empty string
        snippets_with_headers.append(header + body)
    
    return snippets_with_headers

# Streamlit app layout
st.title("🧱 Source Code Analysis & Chatbot App")
st.write("A chatbot-powered app with GenAI-powered source code analysis")

# Initialize variable to hold uploaded code
uploaded_code = ""

# Multi-file upload for source code analysis
uploaded_files = st.file_uploader("Upload your source code files", type=["py", "java", "js", "cpp"], accept_multiple_files=True)

if uploaded_files:
    for uploaded_file in uploaded_files:
        uploaded_code = uploaded_file.getvalue().decode("utf-8")  # Store uploaded code
        
        # Highlight the uploaded code snippet
        highlighted_code = highlight_code(uploaded_code, uploaded_file.type.split('/')[1])
        st.markdown(highlighted_code, unsafe_allow_html=True)

        # Calculate metrics and run security analysis
        complexity, maintainability = calculate_code_metrics(uploaded_code)
        security_report = run_bandit(uploaded_code)

        # Display metrics and security report with improved formatting
        st.write("### Code Quality Metrics")
        
        if complexity:
            st.write(f"Cyclomatic Complexity: {', '.join([f'{func.name} (Complexity: {func.complexity})' for func in complexity])}")
        else:
            st.write("Cyclomatic Complexity: No functions found.")

        st.write(f"Maintainability Index: {maintainability:.2f}")

        st.write("### Security Vulnerability Report")
        
        if security_report['results']:
            for issue in security_report['results']:
                st.write(f"**Issue:** {issue['issue_text']}")
                st.write(f"**Severity:** {issue['issue_severity']}")
                st.write(f"**Confidence:** {issue['issue_confidence']}")
                st.write(f"**Line Number:** {issue['line_number']}")
                st.write(f"**Code Snippet:** `{issue['code'].strip()}`")
                st.write(f"[More Info]({issue['more_info']})")
                st.markdown("---")
        else:
            st.write("No security issues found.")

        if st.button(f"Export Results for {uploaded_file.name}"):
            export_results(complexity, maintainability, security_report)
            st.success("Results exported successfully!")
            
            # Automatically trigger the download immediately after exporting
            with open('analysis_results.csv', 'rb') as f:
                st.download_button("Download Exported Results", f, file_name='analysis_results.csv', key='download_button', use_container_width=True)

# Chatbot Integration
if "messages" not in st.session_state:
    st.session_state.messages = []

# Chat functionality (separate from PDF summarization)
st.subheader("Chat with the Assistant")

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Accept user input for chatbot interaction
if prompt := st.chat_input("Enter your question or message:"):
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})
    # Display user message in chat message container
    with st.chat_message("user"):
        st.markdown(prompt)

    # Prepare chat messages for the assistant
    messages = [
        ChatMessage(role=ChatMessageRole.SYSTEM, content="You are a helpful assistant."),
    ]

    # Add chat history to maintain context
    for msg in st.session_state.messages:
        messages.append(ChatMessage(role=ChatMessageRole.USER if msg["role"] == "user" else ChatMessageRole.ASSISTANT, content=msg["content"]))

    # Query the assistant and append the response
    try:
        response = w.serving_endpoints.query(
            name=serving_endpoint,  # ✅ Using extracted endpoint name
            messages=messages,
            max_tokens=400,
        )
        assistant_response = response.choices[0].message.content

        # Display and save assistant response
        with st.chat_message("assistant"):
            st.markdown(assistant_response)
        st.session_state.messages.append({"role": "assistant", "content": assistant_response})
    except Exception as e:
        st.error(f"Error querying model: {e}")

# Interactive code editing using Ace Editor
code_editor_content = stace.st_ace(
    language='python',
    theme='monokai',
    height=300,
)

# Replace Apply (CTRL+ENTER) with Run Code button 
code = code_editor_content  # Get the content from Ace Editor
   
try:
    output_buffer = io.StringIO()
       
    with contextlib.redirect_stdout(output_buffer):  # Redirect stdout to capture print statements.
        exec(code)  # Execute user code
        
    output = output_buffer.getvalue()  # Get captured output
        
    if output:
        st.write("Output:")
        st.code(output)  # Display captured output from exec()
    else:
        st.write("Code executed successfully with no output.")
   
except Exception as e:
       st.error(f"Error executing code: {e}")



if st.button("Analyze Code"):
    code = code_editor_content  # Get the content from Ace Editor
    
    # Calculate metrics and run security analysis on edited code.
    complexity, maintainability = calculate_code_metrics(code)
    security_report = run_bandit(code)

    # Display metrics and security report for edited code.
    st.write("### Code Quality Metrics")
    
    if complexity:
        st.write(f"Cyclomatic Complexity: {', '.join([f'{func.name} (Complexity: {func.complexity})' for func in complexity])}")
    else:
        st.write("Cyclomatic Complexity: No functions found.")

    st.write(f"Maintainability Index: {maintainability:.2f}")

    st.write("### Security Vulnerability Report")
    
    if security_report['results']:
        for issue in security_report['results']:
            st.write(f"**Issue:** {issue['issue_text']}")
            st.write(f"**Severity:** {issue['issue_severity']}")
            st.write(f"**Confidence:** {issue['issue_confidence']}")
            st.write(f"**Line Number:** {issue['line_number']}")
            st.write(f"**Code Snippet:** `{issue['code'].strip()}`")
            st.write(f"[More Info]({issue['more_info']})")
            st.markdown("---")
    else:
        st.write("No security issues found.")