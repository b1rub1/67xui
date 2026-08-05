# ========================================================
# Stage: Frontend (Vite)
# ========================================================
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
COPY internal/web/translation /src/internal/web/translation
RUN npm run build

# ========================================================
# Stage: Build AmneziaWG userspace tools
# amneziawg-tools is a fork of wireguard-tools. The Makefile
# builds a 'wg' binary and renames it to 'awg' on install;
# likewise 'wg-quick/linux.bash' is installed as 'awg-quick'.
# We use 'make install DESTDIR' so renaming is handled for us.
# ========================================================
FROM alpine AS awg-tools
RUN apk add --no-cache \
  build-base \
  git \
  bash \
  pkgconf
RUN git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-tools.git /awg-tools
WORKDIR /awg-tools/src
# WITH_WGQUICK=yes: on Alpine /usr/bin/bash may not exist yet so
# auto-detection fails; force-enable the wg-quick install target.
RUN make && make install WITH_WGQUICK=yes DESTDIR=/awg-out PREFIX=/usr/local

# ========================================================
# Stage: Builder (Go binary)
# golang:1.26-alpine doesn't exist on Docker Hub; use the
# bookworm (Debian) image and compile against musl so the
# resulting binary runs in the Alpine final stage.
# ========================================================
FROM golang:1.26-bookworm AS builder
WORKDIR /app
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
  musl-tools \
  musl-dev \
  curl \
  unzip \
  && rm -rf /var/lib/apt/lists/*

COPY . .
COPY --from=frontend /src/internal/web/dist ./internal/web/dist

ENV CGO_ENABLED=1
ENV CC=musl-gcc
ENV CGO_CFLAGS="-D_LARGEFILE64_SOURCE"
# -extldflags '-static' produces a fully static binary that runs
# on Alpine (musl) even though the builder is Debian (glibc).
RUN go build -ldflags "-w -s -linkmode external -extldflags '-static'" -o build/x-ui main.go
RUN ./DockerInit.sh "$TARGETARCH"

# ========================================================
# Stage: Final Image
# ========================================================
FROM alpine
ENV TZ=Asia/Tehran
WORKDIR /app

RUN apk add --no-cache --update \
  ca-certificates \
  tzdata \
  fail2ban \
  bash \
  curl \
  openssl \
  iproute2 \
  iptables \
  ip6tables \
  wireguard-tools-wg-quick

# Copy AWG userspace tools built from source.
# 'awg' is the config tool (analogous to wg).
# 'awg-quick' is a bash script (analogous to wg-quick); it calls awg + ip.
# 'make install' renamed the binary to 'awg' and the script to 'awg-quick'
# under DESTDIR/usr/local/bin/ — copy them from there.
COPY --from=awg-tools /awg-out/usr/local/bin/awg /usr/local/bin/awg
COPY --from=awg-tools /awg-out/usr/local/bin/awg-quick /usr/local/bin/awg-quick
RUN chmod +x /usr/local/bin/awg /usr/local/bin/awg-quick

COPY --from=builder /app/build/ /app/
COPY --from=builder /app/DockerEntrypoint.sh /app/
COPY --from=builder /app/x-ui.sh /usr/bin/x-ui
COPY --from=builder /app/internal/web/translation /app/internal/web/translation

# Configure fail2ban
RUN rm -f /etc/fail2ban/jail.d/alpine-ssh.conf \
  && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local \
  && sed -i "s/^\[ssh\]$/&\nenabled = false/" /etc/fail2ban/jail.local \
  && sed -i "s/^\[sshd\]$/&\nenabled = false/" /etc/fail2ban/jail.local \
  && sed -i "s/#allowipv6 = auto/allowipv6 = auto/g" /etc/fail2ban/fail2ban.conf

RUN chmod +x \
  /app/DockerEntrypoint.sh \
  /app/x-ui \
  /usr/bin/x-ui

ENV XUI_IN_DOCKER="true"
ENV XUI_MAIN_FOLDER="/app"
ENV XUI_ENABLE_FAIL2BAN="true"
ENV XUI_DB_TYPE=""
ENV XUI_DB_DSN=""
EXPOSE 2053
VOLUME [ "/etc/x-ui" ]
CMD [ "./x-ui" ]
ENTRYPOINT [ "/app/DockerEntrypoint.sh" ]
