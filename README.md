# Automated Investigator

## Requirements

- Python 3.10 & Pip (Only Tested specifically on this version) - needed as the main software runs on Python
- OpenTyphoon API Key (Free) - needed for the actual LLMs interactions and tool-calling
- HybridAnalysis API Key (Free) - needed for the file analysis via HybridAnalysis
- VirusTotal API Key (Free) - needed for the file analysis via VirusTotal 

## Why OpenTyphoon

OpenTyphoon LLM is a Thai-focused LLM developed by SCB 10X, which understand Thai language and nuance at a deeper level than other language models due to the training and finetuning process that are focused on Thai language.

## What can be improved

Due to our technical resources constraint, we may not be able to create an actual model small enough to run fully offline without internet access (through future distillation, training on specific data, and finetuning), while also being fast enough to inference, which might be useful in sensitive environment or to allow the software to run entirely on edge devices, but we did provide a baseline for prompting existing model to follow instruction accurately, and referring to actual environment context as needed, which is one of the key element in utilizing LLMs as a tool.

We also do not have access to Premium APIs for service such as VirusTotal to fully utilize the power of such platform.