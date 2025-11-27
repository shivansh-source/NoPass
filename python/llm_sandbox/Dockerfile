FROM python:3.11-slim

WORKDIR /app

# If you later want to use a real LLM, install here.
# For now, we need nothing extra.
# RUN pip install some-llm-lib

COPY run_llm.py /app/run_llm.py

# The container receives:
#   - /app/input/system.txt
#   - /app/input/user.txt
# and prints a "draft answer" to stdout.
ENTRYPOINT ["python", "/app/run_llm.py"]
