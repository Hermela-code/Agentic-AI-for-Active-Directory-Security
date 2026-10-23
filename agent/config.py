import os


MODEL_NAME = os.getenv(
    "MODEL_NAME",
    "qwen2.5-coder:7b"
)

BACKEND_URL = os.getenv(
    "BACKEND_URL",
    "http://127.0.0.1:8000"
)