FROM python:3.12.11-slim-bookworm AS app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ceilings ./ceilings
USER 101:101
ENTRYPOINT ["python", "-m", "ceilings"]

FROM smallstep/step-cli:0.31.0 AS step
FROM python:3.12.11-alpine3.22 AS pki
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk add --no-cache openssl
COPY --from=step /usr/local/bin/step /usr/local/bin/step
WORKDIR /pki
COPY labs/pki/lab.py /pki/pki_primitives.py
COPY infra/pki/ /pki/
ENTRYPOINT ["python", "/pki/manage_pki.py"]
