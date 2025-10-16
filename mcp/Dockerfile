FROM python:3.11-slim
WORKDIR /app
COPY sentraip_mcp_server.py /app/
RUN pip install fastapi uvicorn requests
EXPOSE 8081
CMD ["uvicorn", "sentraip_mcp_server:app", "--host", "0.0.0.0", "--port", "8081"]
