FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash build-essential file binutils gdb gdbserver gdb-multiarch \
       patchelf checksec python3 python3-dev python3-venv python3-pip \
       python3-pwntools libssl-dev libffi-dev strace ltrace socat \
       netcat-openbsd libc6-dbg ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv --system-site-packages /opt/pwnbridge/pwn \
	&& /opt/pwnbridge/pwn/bin/python -m pip install --no-cache-dir --upgrade 'pwntools==4.15.0' \
    && /opt/pwnbridge/pwn/bin/python -c \
	   'import importlib.metadata as m; assert m.version("pwntools") == "4.15.0"'

ENV PATH=/opt/pwnbridge/pwn/bin:$PATH
ENV HOME=/tmp/pwnbridge-home
WORKDIR /work

CMD ["sleep", "infinity"]
