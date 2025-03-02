import logging
import os
import streamlit as st
import fitz  # PyMuPDF
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.serving import ChatMessage, ChatMessageRole
import io

# Set up logging
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

# Get user info (if applicable)
def get_user_info():
    headers = st.context.headers
    return dict(
        user_name=headers.get("X-Forwarded-Preferred-Username"),
        user_email=headers.get("X-Forwarded-Email"),
        user_id=headers.get("X-Forwarded-User"),
    )

user_info = get_user_info()

# Streamlit app
if "visibility" not in st.session_state:
    st.session_state.visibility = "visible"
    st.session_state.disabled = False

st.title("🧱 Chatbot App")
st.write("A basic chatbot using your own serving endpoint")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Function to extract text from PDF using BytesIO
def extract_pdf_text(pdf_file):
    text = ""
    with fitz.open(stream=pdf_file, filetype="pdf") as doc:
        for page_num in range(doc.page_count):
            page = doc.load_page(page_num)
            text += page.get_text()
    return text

# PDF upload and summarization
uploaded_pdf = st.file_uploader("Upload a PDF file", type=["pdf"])

if uploaded_pdf:
    st.write("Processing PDF...")
    # Read the uploaded PDF file into memory as a BytesIO object
    pdf_file = io.BytesIO(uploaded_pdf.read())
    
    # Extract text from the uploaded PDF
    pdf_text = extract_pdf_text(pdf_file)
    
    if len(pdf_text) > 2000:  # Limit the content size if it's too long
        pdf_text = pdf_text[:2000] + '... (truncated)'

    # Display the PDF content and trigger summarization
    st.text_area("Extracted PDF Text", value=pdf_text, height=200)

    # Send a single request for summarizing the PDF content
    try:
        messages = [
            ChatMessage(role=ChatMessageRole.SYSTEM, content="You are a helpful assistant."),
            ChatMessage(role=ChatMessageRole.USER, content=f"Summarize the following content from the uploaded PDF:\n\n{pdf_text}")
        ]
        
        # Send the request to Databricks model for summarization
        response = w.serving_endpoints.query(
            name=serving_endpoint,  # ✅ Now correctly using extracted endpoint name
            messages=messages,
            max_tokens=400,
        )
        
        # Display the response from the assistant
        assistant_response = response.choices[0].message.content
        st.markdown(assistant_response)

    except Exception as e:
        st.error(f"Error querying model: {e}")

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
