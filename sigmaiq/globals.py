import os


class DEFAULT_DIRS:
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    SIGMA_RULE_DIR = os.path.join(ROOT_DIR, "llm/data/sigma")
    VECTOR_STORE_DIR = os.path.join(ROOT_DIR, "llm/data/vectordb")
