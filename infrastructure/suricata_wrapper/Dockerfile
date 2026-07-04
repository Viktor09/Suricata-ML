FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ALERTS_PATH=/app/alerts/alerts.json
ENV RULES_FILE=/etc/suricata/rules/dynamic.rules

RUN apt-get update
RUN apt-get install -y python3 python3-pip python3-venv software-properties-common
RUN add-apt-repository ppa:oisf/suricata-stable

RUN apt-get update

RUN apt-get install -y suricata

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /app/venv

COPY suricata_wrapper.py .

CMD ["/app/venv/bin/python", "suricata_wrapper.py"]
