run apk --update add --no-cache rsyslog

run wget -q https://raw.githubusercontent.com/demisto/dockerfiles/syslog/docker/rsyslog/rsyslog.conf --no-check-certificate \
&& rm -rf /etc/rsyslog.conf

run mv rsyslog.conf /etc/rsyslog.conf

run echo "*.* @@`hostname -i`:5140" >> /etc/rsyslog.conf