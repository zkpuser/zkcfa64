FROM rust:1-bookworm

# zkcfa64 has no rust-toolchain file and builds with the image's default
# stable toolchain (needs >= 1.85 for edition 2024). The binius64 submodule
# pins 1.97.1 in its rust-toolchain.toml. The application crate is a sibling,
# so rustup would not discover that file from its working directory; install
# and explicitly select the same toolchain for every container command.
RUN rustup toolchain install 1.97.1 --profile minimal
ENV RUSTUP_TOOLCHAIN=1.97.1

WORKDIR /data

CMD ["sleep", "infinity"]
