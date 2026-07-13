# pwnbridge container image

Build and pin the image before using container runtime:

```console
docker build -t ghcr.io/OWNER/pwnbridge-pwn:VERSION packaging/container
docker push ghcr.io/OWNER/pwnbridge-pwn:VERSION
docker inspect --format '{{index .RepoDigests 0}}' ghcr.io/OWNER/pwnbridge-pwn:VERSION
```

Put the resulting digest in `.pwnbridge.toml`. Pwnbridge runs the container as
the remote account's numeric UID/GID, mounts the workspace at `/work`, does not
mount the engine socket, and grants only the ptrace capability/security setting
needed by GDB.
