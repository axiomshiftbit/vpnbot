import json,socket,time,threading
from pathlib import Path
ip=Path('/private-target-ip').read_text().strip()
def public_second():
 server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('11.77.0.2',9997))
 while True:
  data,peer=server.recvfrom(65535);server.sendto(data,peer)
threading.Thread(target=public_second,daemon=True).start()
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((ip,9998))
while True:
 data,peer=sock.recvfrom(65535)
 with open('/private-udp-received.jsonl','a') as stream:stream.write(json.dumps({'time':time.time(),'destination':ip,'peer':peer[0],'payload_hex':data.hex()})+'\n')
 sock.sendto(data,peer)
