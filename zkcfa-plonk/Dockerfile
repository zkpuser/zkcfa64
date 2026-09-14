FROM rust:1-bookworm

# zkcfa/rust-toolchain requests the "stable" channel, which is not the same
# rustup name as the image's pinned default (e.g. "1.88.0"). Install it now
# so cargo doesn't download a toolchain on first use in a fresh container.
RUN rustup toolchain install stable --profile minimal

WORKDIR /data

CMD ["sleep", "infinity"]
