# Build the homelab mock provider from the ORBIT workspace root:
#   docker build -f deploy/mock-provider/Dockerfile -t orbit-mock-provider .
FROM rust:1.88-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p orbit-mock-provider

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/orbit-mock-provider /usr/local/bin/orbit-mock-provider
ENV ORBIT_MOCK_BIND=0.0.0.0:8088
EXPOSE 8088
ENTRYPOINT ["/usr/local/bin/orbit-mock-provider"]
