FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY agenttrail ./agenttrail
RUN pip install --no-cache-dir .
ENV AGENTTRAIL_DATA_DIR=/data
EXPOSE 8000
CMD ["uvicorn", "agenttrail.app:app", "--host", "0.0.0.0", "--port", "8000"]
