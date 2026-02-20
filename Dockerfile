FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY Pipfile /app/Pipfile

RUN pip install --no-cache-dir pipenv \
    && pipenv lock \
    && pipenv sync --system

COPY . /app

RUN chmod +x /app/docker/entrypoint.sh

EXPOSE 8000

CMD ["/app/docker/entrypoint.sh"]
