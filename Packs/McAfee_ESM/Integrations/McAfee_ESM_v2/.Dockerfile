FROM devtestdemisto/python3:3.8.5.10455-1bf8685d265478ea322139761f5e8733
RUN mkdir -p /devwork/
WORKDIR /devwork
COPY . .
RUN chown -R :4000 /devwork
RUN chmod -R 775 /devwork
