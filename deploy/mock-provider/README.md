# ORBIT Mock Provider (homelab)

A deterministic HTTP server for v0.2 async-adapter conformance. It speaks:

- OpenAI-compatible SSE: `POST /v1/chat/completions`
- Anthropic Messages SSE: `POST /v1/messages`
- Ollama NDJSON: `POST /api/chat`

## Docker

```bash
docker build -f deploy/mock-provider/Dockerfile -t orbit-mock-provider .
docker run --rm -p 8088:8088 orbit-mock-provider
```

## Binary / systemd

```bash
cargo build --release -p orbit-mock-provider
sudo install -m 0755 target/release/orbit-mock-provider /usr/local/bin/
sudo useradd --system --no-create-home orbit 2>/dev/null || true
sudo install -m 0644 deploy/mock-provider/orbit-mock-provider.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now orbit-mock-provider
```

## Script behavior

Set `x-orbit-behavior` on the request: `success`, `partial`, `rate-limit`,
`server-error`, `malformed`, `slow`, or `tool-calls`.
