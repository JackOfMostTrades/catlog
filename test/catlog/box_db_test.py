import base64
import shutil
import tempfile
from unittest import TestCase

from catlog import box_db
from catlog import catlog_pb2


class TestBoxDb(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.box_root = tempfile.mkdtemp()
        cls.box_db = box_db.BoxDb(cls.box_root)

    @classmethod
    def tearDownClass(cls):
        cls.box_db.close()
        shutil.rmtree(cls.box_root)

    def test_set_and_get_config(self):
        self.box_db.set_config('foo', 'bar')
        self.assertEqual('bar', self.box_db.get_config('foo'))

    def test_set_and_get_box_refs(self):
        self.box_db.set_box_refs(base64.b64decode("rsBwZF/lPuOzdjBZN2E08FjMM3JHyXit0Xi2zN+wAZ8="),
                                 [
                                     catlog_pb2.LogEntryReference(
                                         log_id=base64.b64decode("ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs="),
                                         leaf_hash=base64.b64decode("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0="),
                                     ),
                                     catlog_pb2.LogEntryReference(
                                         log_id=base64.b64decode("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y="),
                                         leaf_hash=base64.b64decode("GKw+c0PwFokMUQ6T+TUmEWnZ4/VlQ2Qpgw+vCTT0+OQ=")
                                     )
                                 ])
        self.assertEqual(base64.b64decode("rsBwZF/lPuOzdjBZN2E08FjMM3JHyXit0Xi2zN+wAZ8="),
                         self.box_db.get_box_fingerprint_sha256())
        box_refs = self.box_db.get_box_refs()
        self.assertEqual(2, len(box_refs))
        self.assertTrue((base64.b64decode("ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs="),
                         base64.b64decode("PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0=")) in box_refs)
        self.assertTrue((base64.b64decode("Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y="),
                         base64.b64decode("GKw+c0PwFokMUQ6T+TUmEWnZ4/VlQ2Qpgw+vCTT0+OQ=")) in box_refs)

    def test_file_lifecycle(self):
        self.box_db.set_file_status(box_db.FileStatus(filename="cat.log"))
        files = self.box_db.get_all_files()
        self.assertTrue("cat.log" in [x.filename for x in files])

        file = self.box_db.get_file_status("cat.log")
        file.upload_offset = 1000
        file.upload_complete = False
        file.upload_fingerprint_sha256 = None
        self.committed = False
        self.log_entries = []
