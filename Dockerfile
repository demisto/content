# Last modified: 2026-06-14T04:48:37.982929+00:00

FROM demisto/python3:3.12.13.10116658


COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
