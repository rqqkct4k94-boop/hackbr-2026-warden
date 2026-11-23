import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.request import Request, urlopen


HERE = Path(__file__).resolve().parent


def get_json(url, method='GET'):
    with urlopen(Request(url, method=method), timeout=5) as response:
        return json.load(response)


class DemoProcessTests(unittest.TestCase):
    def test_separate_custodian_cli_live_dashboard_and_restart(self):
        with tempfile.TemporaryDirectory(prefix='warden-demo-runtime-') as temp:
            runtime=Path(temp)/'runtime'
            prep=subprocess.run([sys.executable,str(HERE/'serve_demo.py'),'prepare','--runtime',str(runtime)],
                                check=True,capture_output=True,text=True,timeout=25)
            proof=json.loads(prep.stdout)
            self.assertEqual(proof['authorized_operations'],2)
            self.assertEqual(proof['certificates'],2)
            self.assertEqual(len(list((runtime/'custody').glob('*/custody.json'))),3)
            self.assertEqual(list((runtime/'releases').glob('*.json')),[])
            def run_server():
                child=subprocess.Popen([sys.executable,str(HERE/'serve_demo.py'),'serve','--runtime',str(runtime),
                            '--dashboard-port','0','--site-a-port','0','--site-b-port','0','--idle-seconds','3'],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    info=json.loads(child.stdout.readline()); base=info['dashboard']
                    with urlopen(base+'/',timeout=5) as f:
                        self.assertIn('Warden',f.read().decode())
                    state=get_json(base+'/api/state')
                    live=get_json(base+'/api/verify','POST')
                    self.assertTrue(live['verified'])
                    self.assertEqual(len({x['fingerprint'] for x in live['sites']}),2)
                    self.assertTrue(all(x['matches_approved_certificate'] for x in live['sites']))
                    self.assertEqual(state['proof']['head'],proof['head'])
                    self.assertEqual(state['ledger'],'NOT_CONNECTED')
                    # Poll only health after the final user action. It must not delay idle exit.
                    until=time.monotonic()+6
                    polls=0
                    while child.poll() is None and time.monotonic()<until:
                        try:
                            self.assertFalse(get_json(base+'/health')['activity_counted']);polls+=1
                        except (OSError,TimeoutError):break
                        time.sleep(.25)
                    child.wait(timeout=6)
                    self.assertGreater(polls,1)
                    self.assertEqual(child.returncode,0)
                    self.assertIn('persistent state retained',child.stdout.read())
                    return sorted(x['fingerprint'] for x in live['sites']),state['proof']['head']
                finally:
                    if child.poll() is None:child.terminate();child.wait(timeout=5)
                    child.stdout.close();child.stderr.close()
            first=run_server();second=run_server()
            self.assertEqual(first,second,'restarting all listeners must preserve certificate and audit state')


if __name__=='__main__': unittest.main(verbosity=2)

