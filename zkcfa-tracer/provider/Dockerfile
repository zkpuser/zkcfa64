FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ARG DEBIAN_FRONTEND=noninteractive
ARG QEMU_COMMIT=667e1fff878326c35c7f5146072e60a63a9a41c8
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binutils-aarch64-linux-gnu build-essential ca-certificates \
       gcc-aarch64-linux-gnu git libglib2.0-dev libpixman-1-dev \
       ninja-build pkg-config python3 python3-pip python3-tomli \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --filter=blob:none https://gitlab.com/qemu-project/qemu.git /opt/qemu \
    && git -C /opt/qemu checkout "${QEMU_COMMIT}" \
    && test "$(git -C /opt/qemu rev-parse HEAD)" = "${QEMU_COMMIT}" \
    && cd /opt/qemu \
    && ./configure --target-list=aarch64-linux-user,x86_64-linux-user --enable-plugins \
       --disable-system --disable-tools --disable-docs --disable-werror \
    && ninja -C build qemu-aarch64 qemu-x86_64

RUN python3 -m pip install --no-cache-dir \
       capstone==4.0.2 cffi==1.16.0 cryptography==41.0.7 \
       pycparser==2.21 pyelftools==0.29

WORKDIR /provider
COPY . /provider
RUN make test

CMD ["make", "container-demo"]
