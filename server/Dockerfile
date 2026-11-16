FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV TZ=Asia/Shanghai
ENV HOME=/home/ai-agent

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1003 ai-agent && \
    useradd -u 1003 -g 1003 -d /home/ai-agent -M -s /bin/bash ai-agent

WORKDIR /app
COPY switch_server.py /app/switch_server.py
COPY web_admin.py /app/web_admin.py

EXPOSE 39107/tcp 8788/tcp

ENTRYPOINT ["python3", "/app/switch_server.py"]
CMD ["--config", "/home/ai-agent/switch-server/config.json"]
