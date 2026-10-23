FROM itsafeaturemythic/mythic_python_go:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        osslsigncode openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install mythic_container==0.7.0rc9 cryptography
RUN pip3 install --upgrade --force-reinstall "grpcio>=1.78.0"

WORKDIR /Mythic/

COPY [".", "."]

CMD ["python3", "main.py"]
