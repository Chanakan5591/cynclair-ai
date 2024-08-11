from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool
from langchain_core.messages import HumanMessage, SystemMessage
import streamlit as st

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

@tool
def execute_aql(aql: str) -> str:
    """Interact with QRadar SIEM using Ariel Query Language
    
    Args:
        aql: The Ariel Query Language statement to execute to the server and returns query result. MUST be a valid AQL statement
    """
    print(aql)
    return '["10.23.1.3", "102.10.55.12", "22.104.100.2"]' # return placeholder for now

@st.cache_resource
def init():
    load_dotenv() # Load API Key from env (OpenTyphoon API Key, Not actually OpenAI)

    ### BEGIN TOOL CALLING LLMs
    tools = [execute_aql]

    tool_llm = ChatOpenAI(model="typhoon-v1.5-instruct-fc", base_url="https://api.opentyphoon.ai/v1") # function calling LLMs specifically for interacting with tools
    llm_with_tools = tool_llm.bind_tools(tools)
    ### END TOOL CALLING LLMs

    ### BEGIN CHAT LLMs
    chat_llm = ChatOpenAI(model="typhoon-v1.5x-70b-instruct", base_url="https://api.opentyphoon.ai/v1") # Utilize a smarter LLMs for analysis and chat
    ### END CHAT LLMs

    return (llm_with_tools, chat_llm)

### START INFERENCE

tool_llm, chat_llm = init()

# Human query
if query := st.chat_input("What do you need?"):
    with st.chat_message("user"):
        st.markdown(query)
    
    # append human query to tool messages for the tool calling
    st.session_state['tool_messages'].append(HumanMessage(query))
    # append human query to chat messages as a context to be respond
    st.session_state['chat_messages'].append(HumanMessage(query))

    # Start by calling tool-calling LLMs for gathering informations or doing actions
    ai_msg = tool_llm.invoke(st.session_state['tool_messages'])
    st.session_state['tool_messages'].append(ai_msg)

    for tool_call in ai_msg.tool_calls:
        selected_tool = {"execute_aql": execute_aql}[tool_call["name"].lower()]
        tool_output = selected_tool.invoke(tool_call["args"])
        st.session_state['chat_messages'].append(SystemMessage(tool_output, tool_call_id=tool_call['id'])) # Add Tool Responses to chat messages so that chat LLMs have the responses

    chat_ai_msg = chat_llm.invoke(st.session_state['chat_messages'])
    with st.chat_message("assistant"):
        st.markdown(chat_ai_msg.content)

    st.session_state['chat_messages'].append(chat_ai_msg)
    ### END INFERENCE