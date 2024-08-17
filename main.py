# datetime parsing
from datetime import datetime, timedelta
import datetime as dt

# Parsing JSON
import json

# Regex
import re

# To write JSON output temporarily to file
import tempfile

# For loading API Keys from the env
from dotenv import load_dotenv
import os

# LLMs
from langchain_openai import ChatOpenAI
from langchain_core.tools import create_retriever_tool, tool
from langchain_core.messages import HumanMessage, SystemMessage, AIMessage, BaseMessage

## LLMs RAGs
from langchain_chroma import Chroma
from langchain_community.embeddings.sentence_transformer import (
    SentenceTransformerEmbeddings,
)
from langchain_community.document_loaders import JSONLoader
from langchain_text_splitters import RecursiveJsonSplitter

# Web UI
import mesop as me
import mesop.labs as mel

# Dataclasses
from dataclasses import field

# TI Lookup
from cyntelligence import IPEnrich

# CACHING
from functools import cache

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

If you think you dont need to call any tools, or there are already enough context, use the tool "direct_response" to send the information to another LLMs for analysis. When dealing with epoch timestamp, you must use `convert_timestamp_to_datetime_utc7` tool to convert the timestamp to human readable format of UTC+7. You can use the tool "retrieval_tool" to actually get the context from chroma retriever if you think you have already fetched the information. Provide an argument as the string of ip, hash, etc or natural language to the tool "retrieval_tool" to get the context from the database, include platform name in the query if you want to get the context for that platform. If there is a past request with tool response of "<ADDED_TO_RETRIEVER>", then you can use the tool "retrieval_tool" to get the context from the database directly.
"""

chat_system = """
You are a chat LLM that will help with cybersecurity, you are working in SOC, you will be taking Tool responses from the tool-calling LLMs (which will be in the context as System Message) and interpret them nicely to respond to the user according to their question.
Software stack used are as follow:

- IBM QRadar: Main SIEM
- Swimlane: Playbook

You will not mention those stacks unless mentioned by the user, these are for your own information. You will use markdown to format. You will always respond in Thai.
"""

@me.stateclass
class State:
    tool_messages: list[dict] = field(default_factory=lambda: [{"role": "system", "content": tool_system}])
    chat_messages: list[dict] = field(default_factory=lambda: [{"role": "system", "content": chat_system}])

@cache
def get_chroma():
    embedding_function = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
    return Chroma(collection_name="investigation-context", embedding_function=embedding_function)

@cache
def pre_init():
    db = get_chroma()
    retriever = db.as_retriever()
    retrieval_tool = create_retriever_tool(retriever, "investigation_context", "Context for the investigation that came from tools, use it to answer the user's question")

    splitter = RecursiveJsonSplitter()
    
    return (db, retrieval_tool, splitter)

db, retrieval_tool, splitter = pre_init()

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
def get_info_tip_ip(ip_addresses: list[str]) -> str:
    """Interact with Threat Intelligence Platforms for getting information related to IP addresses

    Args:
        ip_addresses: A list of ip addresses to be send to Threat Intelligence Platform
    """
    ip_enrich = IPEnrich(ip_addresses)
    info = ip_enrich.get_all_info()
    
    with tempfile.NamedTemporaryFile(mode='w', delete=True) as f:
        docs = splitter.split_json(json_data=info, convert_lists=True)
        
        # temp file save and load via jsonloader
        f.write(json.dumps(docs))

        loader = JSONLoader(f.name, jq_schema='.[]', text_content=False)
        docs = loader.load()
        db.add_documents(docs)

        f.close()

    return "<ADDED_TO_RETRIEVER>"

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


tools = [retrieval_tool, execute_aql, get_info_vt_hash, direct_response, convert_timestamp_to_datetime_utc7, get_info_tip_ip]

def init():
    load_dotenv() # Load API Key from env (OpenTyphoon API Key, Not actually OpenAI)
    ### BEGIN TOOL CALLING LLMs

    tool_llm = ChatOpenAI(model="typhoon-v1.5-instruct-fc", temperature=0, base_url="https://api.opentyphoon.ai/v1") # function calling LLMs specifically for interacting with tools
    llm_with_tools = tool_llm.bind_tools(tools)
    ### END TOOL CALLING LLMs

    ### BEGIN CHAT LLMs
    chat_llm = ChatOpenAI(model="typhoon-v1.5x-70b-instruct", temperature=0.7, base_url="https://api.opentyphoon.ai/v1", streaming=True) # Utilize a smarter LLMs for analysis and chat
    ### END CHAT LLMs


    return (llm_with_tools, chat_llm)

### START INFERENCE

tool_llm, chat_llm = init()

### Util function to deduplicate any context
def deduplicate_system_role(messages):
    seen_content = set()
    result = []

    for d in messages:
        if d.get('role') == 'system':
            content = d.get('content')
            if content == '<ADDED_TO_RETRIEVER>':
                continue
            if content not in seen_content:
                seen_content.add(content)
                result.append(d)
    
    return result

### UI Setup
def on_load(e: me.LoadEvent):
    me.set_theme_mode('system')

@me.page(path='/', title='Chat With SOC', on_load=on_load)
def page():
    mel.chat(transform, title="Chat With SOC", bot_user="Automated Investigator")

def process_tool_calls(tool_calls, state, ai_msg, tool_llm):
    if not tool_calls:
        return
    
    print("AI MSG:", ai_msg.content)
    
    tool_call = tool_calls[0]
    selected_tool = {"retrieval_tool": retrieval_tool, "execute_aql": execute_aql, "get_info_vt_hash": get_info_vt_hash, "direct_response": direct_response, "convert_timestamp_to_datetime_utc7": convert_timestamp_to_datetime_utc7, "get_info_tip_ip": get_info_tip_ip}[tool_call["name"].lower()]
    tool_output = selected_tool.invoke(tool_call["args"])

    state.tool_messages.append({"role": "tool", "content": tool_output, "tool_call_id": tool_call['id']})

    print("OUT:", tool_output)

    if "<ADDED_TO_RETRIEVER>" in tool_output:
        state.tool_messages.append({"role": "user", "content": "Use the tool \"retrieval_tool\" to get the context from the database."})

        # Invoke the tool LLMs again to get the context from the database
        ai_msg = tool_llm.invoke(state.tool_messages)

        state.tool_messages.append(ai_msg.dict())

        # Recursive call to process remaining tool calls
        process_tool_calls(ai_msg.tool_calls, state, ai_msg, tool_llm)
    else:
        state.chat_messages.append({"role": "system", "content": tool_output})  # Add Tool Responses to chat messages so that chat LLMs have the responses state
        

def transform(input: str, history: list[mel.ChatMessage]):
    state = me.state(State)
    # update the state with the new input
    state.tool_messages.append({"role": "user", "content": input})
    state.chat_messages.append({"role": "user", "content": input})

    # Start by calling tool-calling LLMs for gathering informations or doing actions
    ai_msg = tool_llm.invoke(state.tool_messages)
    state.tool_messages.append(ai_msg.dict())

    print("Tool LLM Response:", ai_msg)

    process_tool_calls(ai_msg.tool_calls, state, ai_msg, tool_llm)

    for chunk in chat_llm.stream(state.chat_messages):
        yield chunk.content

    state.chat_messages.append({"role": "assistant", "content": chunk.content})

    state.chat_messages = deduplicate_system_role(state.chat_messages)
    state.tool_messages = deduplicate_system_role(state.tool_messages)