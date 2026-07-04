FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

ENV PCAP_DIR=/app/pcaps
ENV OUTPUT_DIR=/app/output
ENV CICFLOW_DIR=/app/CICFlowMeter
ENV MODEL_DIR=/app/model_ddos
ENV LIVE_PCAP=/app/live_capture.pcap
ENV ALERTS_PATH=/app/alerts/alerts.json
ENV INTERFACE=virbr-labs

ENV LD_LIBRARY_PATH=/app/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425:/usr/lib/x86_64-linux-gnu

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    tcpdump \
    iproute2 \
    openjdk-8-jdk \
    git \
    maven \
    libpcap0.8 \
    file \
    && ln -sf /usr/lib/x86_64-linux-gnu/libpcap.so.0.8 /usr/lib/x86_64-linux-gnu/libpcap.so \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/ahlashkari/CICFlowMeter.git /app/CICFlowMeter

RUN chmod +x /app/CICFlowMeter/gradlew

RUN mvn install:install-file \
    -Dfile=/app/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
    -DgroupId=org.jnetpcap \
    -DartifactId=jnetpcap \
    -Dversion=1.4.1 \
    -Dpackaging=jar

RUN sed -i '/args = /c\    args = ["/app/pcaps/", "/app/output/"]' /app/CICFlowMeter/build.gradle

RUN mkdir -p /app/pcaps /app/output /app/alerts && \
    chmod 777 /app/pcaps /app/output /app/alerts

RUN cd /app/CICFlowMeter && ./gradlew build -x test

RUN python3 -m venv /app/venv

COPY requirements.txt .

RUN /app/venv/bin/pip install --upgrade pip && \
    /app/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY ddos_model.py .

COPY model_ddos/ ./model_ddos/

CMD ["/app/venv/bin/python", "ddos_model.py"]
