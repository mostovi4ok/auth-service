FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:b6007a73910218ab068c7a9a7fb91e68f97017ab486af0ecd00403561a64e573

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Novosibirsk
ENV HOME=/app

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

COPY ./pyproject.toml ./uv.lock $VIRTUAL_ROOT/

RUN uv venv ${VIRTUAL_ENV} --no-python-downloads

RUN --mount=type=cache,target=$UV_CACHE_DIR \
    cd ${VIRTUAL_ROOT} && \
    uv sync \
    --locked \
    --no-dev \
    --no-install-workspace

COPY . .

EXPOSE 8000

CMD ["fastapi", "run", "src/main.py", "--reload"]
