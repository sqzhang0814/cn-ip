/ip firewall address-list remove [find list=CN_IP]
/ip firewall address-list add list=CN_IP address=<html> comment="China_IP"
/ip firewall address-list add list=CN_IP address=<head><title>404 Not Found</title></head> comment="China_IP"
/ip firewall address-list add list=CN_IP address=<body> comment="China_IP"
/ip firewall address-list add list=CN_IP address=<center><h1>404 Not Found</h1></center> comment="China_IP"
/ip firewall address-list add list=CN_IP address=<hr><center>openresty</center> comment="China_IP"
/ip firewall address-list add list=CN_IP address=</body> comment="China_IP"
/ip firewall address-list add list=CN_IP address=</html> comment="China_IP"
