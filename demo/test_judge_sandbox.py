import unittest
from judge_sandbox import manifest


class ManifestTests(unittest.TestCase):
    def test_only_metadata_allowlist_survives(self):
        def reader(project,*args):
            self.assertEqual(project,'judge-test-26')
            return {'name':'demo-instance','zone':'projects/judge-test-26/zones/us-central1-a','status':'RUNNING','serviceAccounts':[{'email':'test-secret@example.invalid'}],'metadata':{'items':[{'key':'test-key','value':'secret-placeholder'}]},'networkInterfaces':[{'networkIP':'10.0.0.1'}]}
        report=manifest('judge-test-26',[('vm','Demo compute','demo-instance','us-central1-a','')],reader,lambda _:None)
        self.assertEqual(report['assets'],[{'kind':'vm','alias':'Demo compute','region':'us-central1-a','status':'running'}])
        self.assertNotIn('judge-test-26',str(report));self.assertNotIn('secret',str(report));self.assertNotIn('10.0.0.1',str(report))

    def test_refuses_unmatched_provider_result(self):
        with self.assertRaises(ValueError):manifest('judge-test-26',[('disk','Volume','test-disk','us-central1-a','')],lambda *x:{'name':'unrelated','zone':'zones/us-central1-a'},lambda _:None)

    def test_refuses_flags_or_wildcards_without_cloud_read(self):
        for name in ('--project=prod','*','https://sample.invalid'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                manifest('judge-test-26',[('vm','Only test',name,'us-central1-a','')],lambda *x:self.fail('unexpected provider read'),lambda _:None)

    def test_rejects_duplicate_aliases(self):
        with self.assertRaises(ValueError):manifest('judge-test-26',[('vm','Demo','one','us-central1-a',''),('disk','demo','two','us-central1-a','')],lambda *x:self.fail('unexpected read'),lambda _:None)

    def test_checks_cloud_credentials_first(self):
        def unauthorized(_):raise RuntimeError('no auth')
        with self.assertRaises(RuntimeError):manifest('judge-test-26',[('vm','VM','one','us-central1-a','')],lambda *x:self.fail('unexpected read'),unauthorized)

    def test_bucket_from_a_different_project_is_denied(self):
        def reader(project,*args):
            if args[0]=='storage':return {'name':'demo-bucket','project_number':'123','location':'US'}
            return {'projectNumber':'456'}
        with self.assertRaises(ValueError):manifest('judge-test-26',[('bucket','Objects','demo-bucket','','')],reader,lambda _:None)


if __name__=='__main__':unittest.main()
