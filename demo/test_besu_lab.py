import unittest
from besu_lab import build_compose, genesis_input, verify_network, image_pin, rpc_for, CHAIN_ID, PORTS


class OfflineConfigTests(unittest.TestCase):
    def test_four_isolated_nodes_without_public_rpc(self):
        cfg=build_compose('hyperledger/besu:25.10.0',[f'{n:0128x}' for n in range(1,5)])
        self.assertEqual(len(cfg['services']),4);self.assertTrue(cfg['networks']['warden_lab']['internal'])
        for i,svc in enumerate(cfg['services'].values()):
            self.assertEqual(svc['ports'],[f'127.0.0.1:{PORTS[i]}:8545']);self.assertEqual(svc['mem_limit'],'4g')
            self.assertNotIn('*',' '.join(svc['command']));self.assertIn('--rpc-http-api=ETH,NET,QBFT',svc['command'])
        self.assertEqual(genesis_input('0x'+'1'*40)['blockchain']['nodes']['count'],4)
        with self.assertRaises(ValueError):image_pin('hyperledger/besu:latest')
        with self.assertRaises(ValueError):rpc_for({'rpc_hosts':['192.0.2.1']*4})

    def test_verifier_logic_with_explicit_mock_rpc_fixture(self):
        vals=['0x'+f'{i:040x}' for i in range(1,5)]; heights={p:10 for p in PORTS}
        def mocked(port,method,params=None):
            if method=='eth_chainId':return hex(CHAIN_ID)
            if method=='qbft_getValidatorsByBlockNumber':return vals
            if method=='eth_blockNumber':return hex(heights[port])
            if method=='net_peerCount':return '0x3'
            if method=='eth_getBlockByNumber':return {'hash':'0x'+('a' if params[0]=='0x0' else 'b')*64}
            raise AssertionError(method)
        def advance(_):
            for p in PORTS:heights[p]+=2
        self.assertTrue(verify_network({'chain_id':CHAIN_ID,'validators':vals},mocked,advance)['verified'])
        with self.assertRaises(RuntimeError):verify_network({'chain_id':CHAIN_ID,'validators':vals},mocked,lambda _:None)


if __name__=='__main__':unittest.main(verbosity=2)

