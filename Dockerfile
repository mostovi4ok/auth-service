FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Novosibirsk \
    HOME=/app

ENV VIRTUAL_ROOT=/venv
ENV VIRTUAL_ENV=${VIRTUAL_ROOT}/.venv
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"
ENV UV_CACHE_DIR=/cache/uv

WORKDIR $HOME

RUN apt update -y  && apt install \
    curl \
    gcc \
    libpq-dev \
    libc-dev \
    nano \
    --no-install-recommends -y && apt clean && rm -rf /var/lib/apt/lists/*

COPY ./pyproject.toml ./.python-version ./uv.lock $VIRTUAL_ROOT/

RUN uv venv ${VIRTUAL_ENV} --no-python-downloads

RUN --mount=type=cache,target=$UV_CACHE_DIR \
    cd ${VIRTUAL_ROOT} && \
    uv sync \
    --locked \
    --no-dev \
    --no-install-workspace

COPY . .

EXPOSE 8000

RUN chmod u+x entrypoint.sh

CMD ["/bin/bash", "./entrypoint.sh"]
