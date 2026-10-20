# Diagnostic comparison only: synthetic credentials, loopback listeners, no shell execution.
import argparse, socket, struct, subprocess, tempfile, pathlib, time, json

parser = argparse.ArgumentParser()
parser.add_argument('--rust-server', required=True, type=pathlib.Path)
parser.add_argument('--go-server', required=True, type=pathlib.Path)
args = parser.parse_args()
RUST = str(args.rust_server.resolve(strict=True))
GO = str(args.go_server.resolve(strict=True))
def frame(data, version=4, reserved=0, padding=0):
    return bytes([version, reserved, 0])+struct.pack('!HH', padding, len(data))+data

def start(binary, tmp, name):
    with socket.socket() as s:
        s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    conf=tmp/(name+'.conf')
    conf.write_text(f'[snell-server]\nlisten = 127.0.0.1:{port}\npsk = audit-test-psk-0123456789\nmode = unsafe-raw\n')
    p=subprocess.Popen([binary,'-c',str(conf),'--protocol','v6'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    until=time.monotonic()+5
    while True:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.1): break
        except OSError:
            if p.poll() is not None or time.monotonic()>until: raise RuntimeError('startup failed')
            time.sleep(.01)
    return p,port

def query(port, data):
    with socket.create_connection(('127.0.0.1',port),timeout=.5) as s:
        s.settimeout(.15); s.sendall(data); s.shutdown(socket.SHUT_WR)
        out=b''
        try:
            while True:
                part=s.recv(65536)
                if not part: return ('closed',out.hex())
                out+=part
        except socket.timeout: return ('timeout',out.hex())
        except ConnectionResetError: return ('reset',out.hex())

cases=[]
for cmd in range(256):
    cases.append((f'command-{cmd}',frame(bytes([1,cmd,0]))))
for version in [0,2,255]: cases.append((f'request-version-{version}',frame(bytes([version,0,0]))))
for id_len in [1,16,255]: cases.append((f'ping-no-id-{id_len}',frame(bytes([1,0,id_len]))))
for reserved in [1,255]: cases.append((f'reserved-{reserved}',frame(b'\1\0\0',reserved=reserved)))
for version in [0,1,255]: cases.append((f'header-version-{version}',frame(b'\1\0\0',version=version)))
for pad in [1,65535]: cases.append((f'nonzero-padding-{pad}',frame(b'\1\0\0',padding=pad)))
for n in range(7): cases.append((f'truncated-header-{n}',frame(b'\1\0\0')[:n]))
for data in [b'',b'\1',b'\1\0',b'\1\6\0x',b'\1\6\0',b'\1\1\3x',b'\1\1\0\5abc']:
    cases.append((f'request-{data.hex()}',frame(data)))
# Two complete records: UDP setup followed by invalid / valid datagram address.
for packet in [b'',b'\0',b'\2',b'\1',b'\1\0\7',bytes([1,0,4,127,0,0,1,0,9])+b'data']:
    cases.append((f'udp-record-{packet.hex()}',frame(b'\1\6\0')+frame(packet)))
with tempfile.TemporaryDirectory() as directory:
    procs=[]
    try:
        for name,binary in [('rust',RUST),('go',GO)]: procs.append(start(binary,pathlib.Path(directory),name))
        expected_pong = ('closed', frame(bytes([1])).hex())
        assert query(procs[0][1], frame(bytes([1,0,0]))) == expected_pong
        assert query(procs[1][1], frame(bytes([1,0,0]))) == expected_pong
        differences=[]
        for name,data in cases:
            rust=query(procs[0][1],data); go=query(procs[1][1],data)
            if rust!=go: differences.append(dict(case=name,rust=rust,go=go))
        print(json.dumps(dict(cases=len(cases),differences=differences),indent=2))
    finally:
        for p,_ in procs: p.terminate(); p.wait(timeout=5)
