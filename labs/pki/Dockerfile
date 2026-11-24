FROM smallstep/step-cli:0.31.0 AS smallstep
FROM python:3.12.11-alpine3.22
RUN apk add --no-cache openssl
COPY --from=smallstep /usr/local/bin/step /usr/local/bin/step
WORKDIR /lab
COPY lab.py /lab/lab.py
ENTRYPOINT ["python", "/lab/lab.py"]
