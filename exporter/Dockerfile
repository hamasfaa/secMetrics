FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /exporter

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY secmetrics/ ./secmetrics/

RUN useradd --create-home --uid 10001 exporter \
    && chown -R exporter:exporter /exporter
USER exporter

ENTRYPOINT ["python", "main.py"]
