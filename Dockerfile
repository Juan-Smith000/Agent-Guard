# Local / container deploy. No dependencies to install.
FROM python:3.12-slim
WORKDIR /app
COPY agent_guard/ ./agent_guard/
COPY tests/ ./tests/
COPY eval/ ./eval/
# Real tools need the sandbox files: without this, REAL_TOOLS=1 in
# Docker returns "file not found" for every read, even though the
# guard itself works. The demo DB is created on first use.
COPY data/ ./data/
# Inside a container the server must bind to all interfaces so that
# Docker's -p mapping can reach it. The container itself is still
# only reachable on the port you publish.
ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080
CMD ["python3", "-m", "agent_guard.server"]
