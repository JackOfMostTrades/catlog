import base64
import os.path
import os.path
import random
import shutil
import sys
import tempfile
from io import BytesIO
from unittest import TestCase

from catlog import main
from catlog import stub_crt_sh
from catlog import stub_ct_log
from catlog import stub_le_client
from catlog.box_db import BoxDb
from catlog.catlog_db import CatlogDb


class TestMain(TestCase):
    def setUp(self):
        self.wd = tempfile.mkdtemp()
        os.mkdir(os.path.join(self.wd, ".catlog"))
        os.chdir(self.wd)

        self.crt_sh = stub_crt_sh.StubCrtSh()
        self.ct_log_list = stub_ct_log.StubCtLogList()
        self.ct_log = stub_ct_log.StubCtLog(ct_log_list=self.ct_log_list, crt_sh=self.crt_sh)

    def tearDown(self):
        self.ct_log.stop()
        shutil.rmtree(self.wd)

    def createMain(self):
        catlog_db = CatlogDb(path=os.path.join(self.wd, ".catlog", "catlog.db"))
        le_client = stub_le_client.StubLeClient(ct_log=self.ct_log)

        return main.CatlogMain(catlog_db=catlog_db, ct_log_list=self.ct_log_list, le_client=le_client,
                               crt_sh=self.crt_sh)

    def _run_push_and_pull_test(self, input):
        with self.createMain() as main:
            main.config(["add-domain", "example.com"])
            main.init(["mybox.example.com"])

            with open(os.path.join(self.wd, "foo.bin"), "wb") as f:
                f.write(input)
            main.push(["foo.bin"])

        with BoxDb(os.path.join(self.wd, ".catlog")) as box_db:
            files = box_db.get_all_files()
            assert (len(files) == 1)
            assert (files[0].filename == "foo.bin")
            assert (len(files[0].log_entries) == 1)
            log_entry = files[0].log_entries[0]

        with self.createMain() as main:
            stdout = sys.stdout
            captured = BytesIO()
            sys.stdout = captured
            main.pull([base64.b64encode(log_entry.log_id).decode('utf-8') + "|" + base64.b64encode(
                log_entry.leaf_hash).decode('utf-8')])
            sys.stdout = stdout
            assert (input == captured.getvalue())

    def test_push_and_pull_small_data(self):
        input = bytes(random.getrandbits(8) for _ in range(1024))
        self._run_push_and_pull_test(input)

    def test_push_and_pull_large_data(self):
        input = bytes(random.getrandbits(8) for _ in range(1024 * 1024))
        self._run_push_and_pull_test(input)

    def test_box_lifecycle(self):
        input = bytes(random.getrandbits(8) for _ in range(50 * 1024))

        with self.createMain() as main:
            main.config(["add-domain", "example.com"])
            main.init(["mybox.example.com"])

            with open(os.path.join(self.wd, "foo.bin"), "wb") as f:
                f.write(input)
            main.push(["foo.bin"])
            main.commit([])

        os.remove(os.path.join(self.wd, "foo.bin"))
        os.remove(os.path.join(self.wd, ".catlog", "box.db"))

        with self.createMain() as main:
            main.clone(["mybox.example.com"])
            main.pull(["foo.bin"])

        with open(os.path.join(self.wd, "foo.bin"), "rb") as f:
            data = f.read()

        assert (input == data)
