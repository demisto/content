echo "module(load=\"imudp\")" >> /etc/rsyslog.conf
echo "input(type=\"imudp\" port=\"514\")" >> /etc/rsyslog.conf
echo "*.* @@`hostname -i`:5140" >> /etc/rsyslog.conf