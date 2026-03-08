FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Flask + Gunicorn requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Core network scripts
COPY core/ ./core/

# Flask app
COPY app.py .
COPY templates/ ./templates/
COPY static/ ./static/

# Output directory for temp files
RUN mkdir -p /app/outputs && chmod 777 /app/outputs

EXPOSE 5523

CMD ["python", "-m", "gunicorn", \
     "--bind", "0.0.0.0:5523", \
     "--workers", "4", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--timeout", "300", \
     "--keep-alive", "5", \
     "--log-level", "info", \
     "app:app"]
