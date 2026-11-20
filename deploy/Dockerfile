# The relay as a small image (BLOX.md §8.7). Build from the repository root:
#   docker build -f deploy/Dockerfile -t blox-relay .
#   docker run --rm --network host -e BLOX_LISTEN=localhost:8080 -e BLOX_TRUST_PROXY=1 blox-relay
# Pin the base images by digest for production builds.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p blox-relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/blox-relay /usr/local/bin/blox-relay
ENV BLOX_LISTEN=:8080
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/usr/local/bin/blox-relay"]
