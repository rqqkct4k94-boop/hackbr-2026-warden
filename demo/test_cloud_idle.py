import unittest
from cloud_idle import signed_lease, LeaseReceiver
from warden import ActivityLease


class CloudIdleTests(unittest.TestCase):
    def test_heartbeats_do_not_extend_true_idle(self):
        clock=[1000.0];lease=ActivityLease(lambda:clock[0]);key=b'a'*32
        receiver=LeaseReceiver(key,lambda:clock[0],lambda:clock[0])
        for _ in range(30):
            self.assertTrue(receiver.receive(signed_lease(key,clock[0],lease.remaining_seconds())))
            self.assertEqual(receiver.deadline,1600.0);clock[0]+=15
        clock[0]=1600;self.assertTrue(lease.eligible_for_stop());self.assertTrue(receiver.expired())

    def test_new_real_activity_extends_but_old_or_bad_signature_does_not(self):
        clock=[1000.0];lease=ActivityLease(lambda:clock[0]);receiver=LeaseReceiver(b'a'*32,lambda:clock[0],lambda:clock[0])
        first=signed_lease(b'a'*32,clock[0],lease.remaining_seconds());self.assertTrue(receiver.receive(first))
        clock[0]=1200;lease.user_activity();second=signed_lease(b'a'*32,clock[0],lease.remaining_seconds())
        self.assertTrue(receiver.receive(second));self.assertEqual(receiver.deadline,1800)
        self.assertFalse(receiver.receive(first));self.assertFalse(receiver.receive(signed_lease(b'b'*32,clock[0]+1,500)))
        self.assertEqual(receiver.deadline,1800)


if __name__=='__main__':unittest.main()

