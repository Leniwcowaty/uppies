FROM python:3.13-alpine3.23 AS builder
RUN apk add --no-cache gcc g++ musl-dev python3-dev patchelf binutils
RUN pip install nuitka pyyaml requests cryptography zstandard
COPY main-sqlite.py ./main.py
RUN python3 -m nuitka --standalone --onefile --output-filename=uppies main.py

FROM alpine:3.23
RUN apk add --no-cache libstdc++ gcompat
WORKDIR /uppies
RUN mkdir -p ./uppies-config ./uppies-data
COPY --from=builder /uppies /usr/bin/uppies

CMD ["/usr/bin/uppies"]