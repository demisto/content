sudo echo "module(load=\"imudp\")" >> /etc/rsyslog.conf
sudo echo "input(type=\"imudp\" port=\"514\")" >> /etc/rsyslog.conf
sudo echo "*.* @@`hostname -i`:5140" >> /etc/rsyslog.conf