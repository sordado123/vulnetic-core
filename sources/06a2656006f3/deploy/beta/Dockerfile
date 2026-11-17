FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/vulnetic/data \
    && chown -R 10001:10001 /var/lib/vulnetic
COPY --chmod=755 dist/amd64/vulnetic /usr/local/bin/vulnetic
COPY --chmod=755 dist/amd64/vulnetic-proof-reconcile /usr/local/bin/vulnetic-proof-reconcile
COPY --chmod=755 dist/agents /usr/local/lib/vulnetic/agents
ENV VULNETIC_AGENT_BINARY_DIR=/usr/local/lib/vulnetic/agents
USER 10001:10001
WORKDIR /var/lib/vulnetic
ENTRYPOINT ["/usr/local/bin/vulnetic"]
CMD ["-addr", "0.0.0.0:8787", "-data", "/var/lib/vulnetic/data", "-proxy", ""]
