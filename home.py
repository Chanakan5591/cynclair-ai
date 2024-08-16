# datetime parsing
from datetime import datetime, timedelta
import datetime as dt

# Parsing JSON
import json

# For loading API Keys from the env
from dotenv import load_dotenv
import os

# LLMs
from langchain_openai import ChatOpenAI
from langchain_core.tools import create_retriever_tool, tool
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage

## LLMs RAGs
from langchain_chroma import Chroma
from langchain_community.embeddings.sentence_transformer import (
    SentenceTransformerEmbeddings,
)
from langchain_community.document_loaders import JSONLoader

# Web UI
import streamlit as st

# TI Lookup
from cyntelligence import IPEnrich

# NOTE: preferrably provide all useful tables and columns name within Ariel Database to allow for a more accurate query
tool_system = """
You are a tool-calling LLM that will help with cybersecurity, you are working in SOC, you will utilize all tools you had to help the user when they asked so.
Software stack used are as follow:

- IBM QRadar: Main SIEM
- Swimlane: Playbook

# Ariel DB Information:

## Tables
- events
- flows
- assets_data
- offenses
- asset_properties
- network_hierarchy

## Table: events
### Columns
- starttime / endtime
- sourceip / destinationip
- sourceport / destinationport
- eventname / category
- magnitude
- credibility
- severity
- username
- devicetype
- qid (QRadar ID)

If you think you dont need to call any tools, or there are already enough context, use the tool "direct_response" to send the information to another LLMs for analysis. When dealing with epoch timestamp, you must use `convert_timestamp_to_datetime_utc7` tool to convert the timestamp to human readable format of UTC+7
"""

chat_system = """
You are a chat LLM that will help with cybersecurity, you are working in SOC, you will be taking Tool responses from the tool-calling LLMs (which will be in the context as System Message) and interpret them nicely to respond to the user according to their question.
Software stack used are as follow:

- IBM QRadar: Main SIEM
- Swimlane: Playbook

You will not mention those stacks unless mentioned by the user, these are for your own information. You will use markdown to format. You will always respond in Thai.
"""

if 'tool_messages' not in st.session_state:
    st.session_state['tool_messages'] = [SystemMessage(tool_system)] # All messages between user and tool-calling LLMs in the session

if 'chat_messages' not in st.session_state:
    st.session_state['chat_messages'] = [SystemMessage(chat_system)] # All messages between use and chat LLMs including ToolMessage


@st.cache_resource
def get_chroma():
    embedding_function = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
    return Chroma(collection_name="typhoon-tools", embedding_function=embedding_function)

#@st.cache_resource
#def get_info_vt_hash_request(file_hash: str) -> vt.Object:
def get_info_vt_hash_request(file_hash: str) -> str:
    return ""
#    vt_client = vt.Client(os.environ['VIRUSTOTAL_API_KEY'])
#    info = vt_client.get_object('/files/{}'.format(file_hash))
#    vt_client.close()
#    return info

@tool
def convert_timestamp_to_datetime_utc7(timestamp: float) -> str:
    """Convert an epoch timestamp to UTC+7

    Args:
        timestamp: The epoch timestamp to convert to UTC+7
    """
    utc_datetime = datetime.fromtimestamp(timestamp, dt.UTC)

    # Define the UTC+7 offset
    utc7_offset = timedelta(hours=7)

    # Apply the offset to get the datetime in UTC+7
    utc7_datetime = utc_datetime + utc7_offset

    return str(utc7_datetime)

@tool
def direct_response(res: str) -> str:
    """Send the response information in res argument to analysis LLMs

    Args:
        res: The response information to be sent to the analysis LLMs
    """
    return res

@tool
def execute_aql(aql: str) -> str:
    """Interact with QRadar SIEM using Ariel Query Language for interacting with logs and alerts

    Args:
        aql: The Ariel Query Language statement to execute to the server and returns query result. MUST be a valid AQL statement
    """
    print(aql)
    return '["10.23.1.3", "102.10.55.12", "22.104.100.2"]' # return placeholder for now

@tool
def get_info_vt_ip(ip_address: str) -> str:
    """Interact with VirusTotal (aka VT) for getting information related to IP addresses

    Args:
        ip_address: The ip address to be send to virus total
    """
    ip_enrich = IPEnrich(ip_address)
    info = ip_enrich.get_vt()
    print('\n\n')
    print(info)
    return ""

@tool
def get_info_vt_hash(file_hash: str) -> str:
    """Interact with VirusTotal (aka VT) for getting information related to files via file hash

    Args:
        obj: The file hash to be send to virustotal (Supported All File Hashes type)
    """
    info = get_info_vt_hash_request(file_hash)

    useful_keys = ['last_analysis_stats', 'meaningful_name', 'creation_date', 'last_submission_date']

    final_info = {}

    for key in useful_keys:
        final_info[key] = info.get(key)

    final_info['engines'] = []

    for engine_name, engine_info in info.get('last_analysis_results').items():
        final_info['engines'].append({
            'engine_name': engine_name,
            'method': engine_info['method'],
            'category': engine_info['category'],
            'result': engine_info['result'],
        })

        return "Context: {}\n\nProvide all the information to the user when possible in a nicely structured table format in markdown, only provide 5 engines in the response unless asked otherwise.".format(str(final_info))


@st.cache_resource
def init():
    load_dotenv() # Load API Key from env (OpenTyphoon API Key, Not actually OpenAI)

    ### BEGIN TOOL CALLING LLMs
    tools = [execute_aql, get_info_vt_hash, direct_response, convert_timestamp_to_datetime_utc7, get_info_vt_ip]

    tool_llm = ChatOpenAI(model="typhoon-v1.5-instruct-fc", temperature=0, base_url="https://api.opentyphoon.ai/v1") # function calling LLMs specifically for interacting with tools
    llm_with_tools = tool_llm.bind_tools(tools)
    ### END TOOL CALLING LLMs

    ### BEGIN CHAT LLMs
    chat_llm = ChatOpenAI(model="typhoon-v1.5x-70b-instruct", temperature=0.7, base_url="https://api.opentyphoon.ai/v1", streaming=True) # Utilize a smarter LLMs for analysis and chat
    ### END CHAT LLMs


    return (llm_with_tools, chat_llm)

### START INFERENCE

tool_llm, chat_llm = init()

for chat_message in st.session_state['chat_messages']:
    if type(chat_message) == HumanMessage:
        with st.chat_message("human"):
            st.markdown(chat_message.content)

    if type(chat_message) == AIMessage:
        with st.chat_message("assistant"):
            st.markdown(chat_message.content)

# Human query
if query := st.chat_input("What do you need?"):
    print(st.session_state['tool_messages'])

    print('\n\n')

    print(st.session_state['chat_messages'])
    with st.chat_message("user"):
        st.markdown(query)

    # append human query to tool messages for the tool calling
    st.session_state['tool_messages'].append(HumanMessage(query))
    # append human query to chat messages as a context to be respond
    st.session_state['chat_messages'].append(HumanMessage(query))

    # Start by calling tool-calling LLMs for gathering informations or doing actions
    ai_msg = tool_llm.invoke(st.session_state['tool_messages'])
    st.session_state['tool_messages'].append(ai_msg)
    
    print("Tool LLM Response:", ai_msg)

    for tool_call in ai_msg.tool_calls:
        selected_tool = {"execute_aql": execute_aql, "get_info_vt_hash": get_info_vt_hash, "direct_response": direct_response, "convert_timestamp_to_datetime_utc7": convert_timestamp_to_datetime_utc7, "get_info_vt_ip": get_info_vt_ip}[tool_call["name"].lower()]
        tool_output = selected_tool.invoke(tool_call["args"])
        st.session_state['chat_messages'].append(SystemMessage(tool_output, tool_call_id=tool_call['id'])) # Add Tool Responses to chat messages so that chat LLMs have the responses

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        full_response = ""

        for chunk in chat_llm.stream(st.session_state['chat_messages']):
            full_response += chunk.content
            message_placeholder.markdown(full_response + "▌")

        message_placeholder.markdown(full_response)

    st.session_state['chat_messages'].append(AIMessage(full_response))
    ### END INFERENCE
