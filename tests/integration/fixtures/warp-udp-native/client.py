import ipaddress,json,socket,struct,sys,time

def recv(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise EOFError('SOCKS closed')
        data+=part
    return data

def address(host,port):
    try:
        ip=ipaddress.ip_address(host)
        return bytes([1 if ip.version==4 else 4])+ip.packed+struct.pack('!H',port)
    except ValueError:
        data=host.encode();return bytes([3,len(data)])+data+struct.pack('!H',port)

def reply(s):
    h=recv(s,4)
    if h[1]:raise RuntimeError('SOCKS reply '+str(h[1]))
    if h[3]==1:host=socket.inet_ntop(socket.AF_INET,recv(s,4))
    elif h[3]==4:host=socket.inet_ntop(socket.AF_INET6,recv(s,16))
    elif h[3]==3:host=recv(s,recv(s,1)[0]).decode()
    else:raise ValueError('invalid address type')
    return host,struct.unpack('!H',recv(s,2))[0]

def control(proxy,cmd=3,host='0.0.0.0',port=0,proxy_port=1080):
    s=socket.create_connection((proxy,proxy_port),2);s.settimeout(2)
    s.sendall(b'\x05\x01\x00');assert recv(s,2)==b'\x05\x00'
    s.sendall(bytes([5,cmd,0])+address(host,port))
    return s,reply(s)

def tcp(proxy,target,port=18080,proxy_port=1080):
    with control(proxy,1,target,port,proxy_port)[0] as s:
        s.sendall(b'GET / HTTP/1.0\r\nHost: public.test\r\n\r\n')
        data=b''
        while True:
            b=s.recv(8192)
            if not b:break
            data+=b
            if b"\r\n\r\n" in data:
                headers,body=data.split(b"\r\n\r\n",1)
                lengths=[int(v.split(b":",1)[1]) for v in headers.split(b"\r\n") if v.lower().startswith(b"content-length:")]
                if lengths and len(body)>=lengths[0]:break
        assert b'WARP-UDP-FIXTURE' in data
        return data.split(b'\r\n\r\n')[-1].decode()

def udp(proxy,target,port=18080,fragment=0,close=False,proxy_port=1080,associate_host="0.0.0.0",size=40,count=1):
    s,relay=control(proxy,host=associate_host,proxy_port=proxy_port)
    try:
        assert proxy_port!=1080 or 20000<=relay[1]<=29999,relay
        if relay[0] in ('0.0.0.0','::'):relay=(proxy,relay[1])
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
            u.settimeout(2)
            for index in range(count):
                payload=('WARP-UDP-FIXTURE:'+str(time.monotonic_ns())+':'+str(index)).encode().ljust(size,b'x')
                packet=b'\x00\x00'+bytes([fragment])+address(target,port)+payload
                if close:s.close();time.sleep(.3)
                u.sendto(packet,relay);data,peer=u.recvfrom(65535)
                assert data.endswith(payload),(len(data),peer)
            return {'relay_port':relay[1],'size':len(data),'packets':count}

    finally:s.close()

if __name__=='__main__':
    p=json.loads(sys.stdin.read())
    try:
        fn=p.pop('kind');v={'tcp':tcp,'udp':udp,'control':lambda **kw:control(**kw)[1]}[fn](**p)
        print(json.dumps({'ok':True,'result':v}))
    except Exception as e:print(json.dumps({'ok':False,'error':type(e).__name__+': '+str(e)}))
