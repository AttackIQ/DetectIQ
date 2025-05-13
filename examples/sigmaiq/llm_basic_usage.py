# %% This example will demonstrate how to use SigmAIQ to perform the following:
# %% 1. Download the latest Sigma Rule package release
# %% 2. Create embeddings of the Sigma Rules in the package
# %% 3. Create and save a VectorDB of the Sigma Rule embeddings
# %% 4. Use a similarity search on the VectorDB to find Sigma Rules similar to a provided query

# %% NOTE, this example uses OpenAI for embeddings. Ensure you have an OpenAI API key set in your environment variable
# %% OPENAI_API_KEY

# %% Also ensure you have installed the correct requirements with:
# `pip install -r requirements/common.txt -r requirements/llm.txt`


# %% Create a SigmaLLM object with default settings. See the class docstring for more information
from langchain_openai import OpenAIEmbeddings

# %% Import SigmAIQ LLM and OpenAIEmbeddings
from sigmaiq.llm.base import SigmaLLM

sigma_llm = SigmaLLM(embedding_model=OpenAIEmbeddings(model="text-embedding-3-large"))

# %% The `create_sigma_vectordb()` method will automatically do all the work for you :) (only run this once)
sigma_llm.create_sigma_vectordb(save=True)  # Save locally to disk

# %% Run a similarity search on the vectordb for encoded powershell commands and print top 3 results
query = "Encoded powershell commands"
matching_rules = sigma_llm.simple_search(query, k=3)
for matching_rule in matching_rules:
    print(matching_rule.page_content, end="\n\n-------------------\n\n")

# %% You can also load an existing vector store from disk (recommended)
sigma_llm.load_sigma_vectordb()

query = "certutil"
matching_rules = sigma_llm.simple_search(query, k=3)
for matching_rule in matching_rules:
    print(matching_rule.page_content, end="\n\n-------------------\n\n")
