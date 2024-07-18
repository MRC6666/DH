# DH

网络空间安全课设3

client机ip：192.168.64.128

server机ip：192.168.64.129

./server Port

./middle ClientIP ServerIP

./client ServerIP ServerPort





arpspoof -t 192.168.64.128 192.168.64.129 -i ens33

arpspoof -t 192.168.64.129 192.168.64.128 -i ens33

./server 8888

./middle 192.168.64.128 192.168.64.129

./client 192.168.64.129 8888

ps -ef | grep middle

kill
