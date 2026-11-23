import unittest
from cloudshell_owner import (ALL,NODES,PREFIX,NETWORK,SUBNET,CIDR,REGION,ZONE,LABELS,instance_args,validate_instance,
                              startup_script,validator_installer,CONTROL_INSTALLER,validate_network_recovery)


class OwnerScopeTests(unittest.TestCase):
    def test_exact_bounded_vm_shapes_no_cloud_privileges(self):
        self.assertEqual(len(ALL),5);self.assertEqual(sum(x[2]=='e2-medium' for x in ALL),4)
        self.assertEqual(len({x[1] for x in ALL}),5)
        for node in ALL:
            args=instance_args(node,'/tmp/startup')
            for option in ('--no-service-account','--no-scopes','--no-boot-disk-auto-delete','--deletion-protection','--boot-disk-size=20GB'):
                self.assertIn(option,args)
            self.assertTrue(node[0].startswith(PREFIX)); self.assertIn('--metadata=block-project-ssh-keys=TRUE',args)

    def test_exact_resource_validation_rejects_unrelated_vm(self):
        n=ALL[0]
        actual={'name':n[0],'zone':'zones/'+ZONE,'labels':dict(LABELS),'machineType':'machineTypes/'+n[2],
                'networkInterfaces':[{'networkIP':n[1],'network':'networks/'+NETWORK}],
                'disks':[{'autoDelete':False,'source':'disks/'+n[0],'type':'PERSISTENT'}],
                'tags':{'items':[PREFIX,PREFIX+'-validator']},'status':'RUNNING'}
        self.assertEqual(validate_instance(n,actual)['name'],n[0])
        actual['labels']['scope']='production'
        with self.assertRaises(RuntimeError):validate_instance(n,actual)
        actual['labels']['scope']='synthetic';actual['disks'][0]['autoDelete']=True
        with self.assertRaises(RuntimeError):validate_instance(n,actual)

    def test_bootstrap_guard_and_rpc_private_boundaries(self):
        enodes=[f'enode://{i:0128x}@{n[1]}:30303' for i,n in enumerate(NODES,1)]
        for i,node in enumerate(NODES):
            user_script=validator_installer(i,enodes)
            self.assertIn('--rpc-http-host='+node[1],user_script)
            self.assertIn('--host-allowlist=localhost,127.0.0.1,'+node[1],user_script)
            self.assertIn('warden-bootstrap-guard.timer',user_script)
            self.assertIn('warden-lease.service',user_script)
        self.assertIn('--on-active=600s',startup_script('validator'))
        self.assertIn('ExecStopPost=+/sbin/shutdown -h now',CONTROL_INSTALLER)

    def test_network_only_recovery_preserves_exact_subnet_and_rejects_scope_changes(self):
        networks=[{'name':NETWORK,'autoCreateSubnetworks':False}]
        subnet={'name':SUBNET,'network':'networks/'+NETWORK,'region':'regions/'+REGION,'ipCidrRange':CIDR}
        self.assertFalse(validate_network_recovery(networks,[],[],[],[]))
        self.assertTrue(validate_network_recovery(networks,[subnet],[],[],[]))
        with self.assertRaises(RuntimeError):validate_network_recovery(networks,[{**subnet,'ipCidrRange':'10.1.0.0/24'}],[],[],[])
        with self.assertRaises(RuntimeError):validate_network_recovery(networks,[subnet],[],[{'name':PREFIX+'-v1'}],[])
        with self.assertRaises(RuntimeError):validate_network_recovery(networks,[subnet],[],[],[{'name':PREFIX+'-v1'}])
        with self.assertRaises(RuntimeError):validate_network_recovery(networks,[subnet],[{'name':'not-lab','network':'networks/'+NETWORK}],[],[])
        with self.assertRaises(RuntimeError):validate_network_recovery([{**networks[0],'peerings':[{}]}],[subnet],[],[],[])


if __name__=='__main__':unittest.main()

