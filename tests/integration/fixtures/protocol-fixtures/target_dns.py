import socket,struct
from pathlib import Path
addresses={'anytls.test':'11.77.0.2','public.test':'11.77.0.2','public2.test':'11.77.0.2','private.test':Path('/private-target-ip').read_text().strip()}
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',53))
while True:
 data,peer=s.recvfrom(4096)
 try:
  p=12;labels=[]
  while data[p]:n=data[p];labels.append(data[p+1:p+1+n].decode());p+=n+1
  qtype=struct.unpack('!H',data[p+1:p+3])[0];qend=p+5
  host='.'.join(labels).lower();known=host in addresses;answer=known and qtype==1
  reply=data[:2]+struct.pack('!5H',0x8180 if known else 0x8183,1,int(answer),0,0)+data[12:qend]
  if answer:reply+=b'\xc0\x0c\0\1\0\1\0\0\0\x01\0\x04'+socket.inet_aton(addresses[host])
  s.sendto(reply,peer)
 except (IndexError,UnicodeDecodeError,struct.error):pass
