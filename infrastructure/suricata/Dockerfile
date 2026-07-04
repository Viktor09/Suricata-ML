FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository ppa:oisf/suricata-stable
RUN apt-get update
RUN apt-get install -y suricata jq iproute2
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/suricata /etc/suricata/rules

RUN sed -i -e 's|default-rule-path: /var/lib/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/suricata/suricata.yaml
RUN sed -i -e 's|  - suricata.rules|  - dynamic.rules|g' /etc/suricata/suricata.yaml

RUN sed -i 's/interface: eth0/interface: vl-mirror/g' /etc/suricata/suricata.yaml
RUN sed -i 's/cluster-id: 99/cluster-id: 98/g' /etc/suricata/suricata.yaml

RUN sed -i '/quic:/,/enabled:/{s/enabled: yes/enabled: no/}' /etc/suricata/suricata.yaml
RUN sed -i '/- flow:/,/enabled:/ s/enabled: yes/enabled: no/' /etc/suricata/suricata.yaml
RUN sed -i '/unix-command:/,/enabled:/ s/enabled: no/enabled: yes/' /etc/suricata/suricata.yaml

COPY suricata_start.sh /suricata_start.sh
RUN chmod +x /suricata_start.sh

ENTRYPOINT ["/suricata_start.sh"]
