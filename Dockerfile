FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Novosibirsk \
    HOME=/app

WORKDIR $HOME

RUN apt update -y  && apt install \
    curl \
    gcc \
    libpq-dev \
    libc-dev \
    nano \
    --no-install-recommends -y && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./pyproject.toml ./.python-version ./uv.lock ./

RUN uv pip install -r pyproject.toml --system --no-cache-dir --no-python-downloads

COPY . .

EXPOSE 8000

RUN chmod u+x entrypoint.sh

CMD ["/bin/bash", "./entrypoint.sh"]
