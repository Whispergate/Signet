FROM itsafeaturemythic/mythic_python_go:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        osslsigncode openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install mythic_container==0.6.16 cryptography

WORKDIR /Mythic/

COPY [".", "."]

CMD ["python3", "main.py"]
