apk --update add --no-cache rsyslog

wget -q https://raw.githubusercontent.com/demisto/dockerfiles/syslog/docker/rsyslog/rsyslog.conf --no-check-certificate \
&& rm -rf /etc/rsyslog.conf

mv rsyslog.conf /etc/rsyslog.conf

echo "*.* @@`hostname -i`:5140" >> /etc/rsyslog.conf