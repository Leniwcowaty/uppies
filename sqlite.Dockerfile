FROM alpine:3.23

RUN apk add --no-cache python3 sqlite
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install pyyaml requests cryptography

WORKDIR /uppies
RUN mkdir -p ./uppies-config ./uppies-data
COPY main-sqlite.py .

CMD ["python3", "./main-sqlite.py"]