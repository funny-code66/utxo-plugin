FROM python:3.9-buster

COPY . /app/plugins
WORKDIR /app/plugins

RUN apt-get update
RUN apt-get install -y build-essential cmake musl-dev gcc g++ libffi-dev libssl-dev python2 python2-dev python3-dev curl libkrb5-dev librocksdb-dev libleveldb-dev libsnappy-dev liblz4-dev \
    && pip install scrypt x11_hash \
    && pip3 install -r /app/plugins/requirements.txt \
    && rm -rf /var/cache/apk/* \
    && rm -rf /usr/share/man \
    && rm -rf /tmp/*

ENV ALLOW_ROOT 1
ENV EVENT_LOOP_POLICY="uvloop"

EXPOSE 8000 9000

CMD ["python3", "/app/plugins/main.py"]
