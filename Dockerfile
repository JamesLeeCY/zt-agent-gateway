FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY tools ./tools
COPY gateway ./gateway
COPY data ./data
ENV ZT_VAR_DIR=/app/var OPA_URL=http://opa:8181
EXPOSE 8000
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
