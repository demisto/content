FROM devtestdemisto/python:1.3-alpine-dcdbbf5d2a8a73f69ddaab9ed1cc04f1
RUN mkdir -p /devwork/
WORKDIR /devwork
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
