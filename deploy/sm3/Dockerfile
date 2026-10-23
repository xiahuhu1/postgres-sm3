# Build from the patched source tree, retaining a reproducible PostgreSQL baseline.
ARG BASE_IMAGE=172.16.61.68:8080/library/debian:bookworm
FROM ${BASE_IMAGE} AS build
ARG BUILD_JOBS=4
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bison flex pkg-config libssl-dev zlib1g-dev libreadline-dev \
    libicu-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN ./configure --prefix=/usr/local/pgsql --with-ssl=openssl --with-icu \
    && make -j"${BUILD_JOBS}" && make install \
    && make -C contrib -j"${BUILD_JOBS}" && make -C contrib install

FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 zlib1g libreadline8 libicu72 locales ca-certificates gosu \
    && sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 999 postgres \
    && useradd --uid 999 --gid postgres --home-dir /var/lib/postgresql postgres \
    && mkdir -p /var/lib/postgresql/data /var/run/postgresql \
    && chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql
COPY --from=build /usr/local/pgsql /usr/local/pgsql
COPY deploy/sm3/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENV PATH=/usr/local/pgsql/bin:$PATH \
    LD_LIBRARY_PATH=/usr/local/pgsql/lib \
    PGDATA=/var/lib/postgresql/data \
    PGHOST=/var/run/postgresql \
    LANG=en_US.UTF-8
LABEL org.opencontainers.image.title="PostgreSQL 17.10 SCRAM-SM3" \
      org.opencontainers.image.version="17.10-sm3.2" \
      org.opencontainers.image.source="https://github.com/xiahuhu1/postgres-sm3"
EXPOSE 5432
VOLUME /var/lib/postgresql/data
STOPSIGNAL SIGINT
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD pg_isready -U postgres -d postgres || exit 1
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["postgres"]
