FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV ALERTS_PATH=/app/alerts/alerts.json

RUN apt-get update
RUN apt-get install -y python3 python3-pip python3-venv tshark iproute2
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/alerts
RUN python3 -m venv /app/venv

COPY requirements.txt .

RUN /app/venv/bin/pip install --upgrade pip
RUN /app/venv/bin/pip install -r requirements.txt --no-cache-dir
RUN /app/venv/bin/pip install torch --index-url https://download.pytorch.org/whl/cpu --no-cache-dir


COPY arp_spoofing_model.py .
COPY arp_model_deploy.pkl .

CMD ["/app/venv/bin/python", "-u", "/app/arp_spoofing_model.py"]
