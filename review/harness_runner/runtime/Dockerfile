# Runtime for case harnesses (contract v1). No network at run time; everything needed is baked in here.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-flask python3-jinja2 python3-yaml python3-lxml \
      nodejs npm openjdk-17-jdk-headless ca-certificates findutils procps \
 && npm install -g typescript@5.6.3 \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /root/.npm \
 && useradd -m -u 1000 runner
USER runner
WORKDIR /tmp
