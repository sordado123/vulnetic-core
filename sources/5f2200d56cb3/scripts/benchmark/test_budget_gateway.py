import json,subprocess,sys,tempfile,threading,time,unittest,urllib.request,urllib.error,socket
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class GatewayTest(unittest.TestCase):
 def test_admission_and_missing_usage(self):
  state={'count':0,'usage':True}
  class Upstream(BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_POST(self):
    state['count']+=1;self.rfile.read(int(self.headers['Content-Length']))
    result={'choices':[]}
    if state['usage']:result['usage']={'prompt_tokens':20,'completion_tokens':5}
    body=json.dumps(result).encode();self.send_response(200);self.end_headers();self.wfile.write(body)
  upstream=ThreadingHTTPServer(('127.0.0.1',0),Upstream);threading.Thread(target=upstream.serve_forever,daemon=True).start()
  with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
  with tempfile.TemporaryDirectory() as folder:
   config=Path(folder)/'config.json';config.write_text(json.dumps({'base_url':f'http://127.0.0.1:{upstream.server_port}','api_key':'test-only','client_token':'client','admin_token':'admin','port':port}),encoding='utf-8')
   process=subprocess.Popen([sys.executable,str(Path(__file__).with_name('budget_gateway.py')),str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   def req(path,body=None,key='client'):
    request=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=None if body is None else json.dumps(body).encode(),headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
    try:
     with urllib.request.urlopen(request,timeout=3) as response:return response.status,json.loads(response.read())
    except urllib.error.HTTPError as error:return error.code,json.loads(error.read())
   try:
    for _ in range(60):
     try:req('/usage',key='admin');break
     except OSError:time.sleep(.05)
    payload={'model':'deepseek-ai/DeepSeek-V4.1-Flash-1017','max_tokens':4096,'stream':False,'messages':[]}
    self.assertEqual(req('/v1/chat/completions',payload)[0],402);self.assertEqual(state['count'],0)
    self.assertEqual(req('/control',{'run':'artex-1'},'client')[0],404)
    self.assertEqual(req('/control',{'run':'artex-1'},'admin')[0],200)
    self.assertEqual(req('/v1/chat/completions',payload)[0],200)
    state['usage']=False;self.assertEqual(req('/v1/chat/completions',payload)[0],502)
    self.assertEqual(req('/v1/chat/completions',payload)[0],402);self.assertEqual(state['count'],2)
   finally:process.terminate();process.wait(timeout=5);upstream.shutdown();upstream.server_close()
if __name__=='__main__':unittest.main()
