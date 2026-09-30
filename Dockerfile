# ULPF — SIH26156
# Build once with network access, then run with --network none for
# air-gapped deployment (requirement j). No runtime downloads, no
# external calls of any kind after this image is built.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY core/ ./core/
COPY api/ ./api/
COPY sample_logs/ ./sample_logs/

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
