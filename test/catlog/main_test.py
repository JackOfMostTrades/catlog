import base64
import hashlib
import os.path
import random
from unittest import TestCase

from . import main


class TestMain(TestCase):
    def test_push_small_data(self):
        input = bytes(random.getrandbits(8) for _ in range(1024))
        refs = main.push_data(input)
        print(refs)

    def test_push_data(self):
        with open(os.path.expanduser("~/Downloads/grumpycat.jpg"), "rb") as f:
            data = f.read()
        refs = main.push_data(data)
        print(refs)

    def test_pull_data(self):
        data = main.pull_data(base64.b64decode("sMyD5aX5fWuvfAnMKEkEhyrH6IsTLGNQt8b9JuFsbHc="),
                              base64.b64decode("so5TCswKqL9afHRcEUeyAGRP0TjB4AXNx/gcA0SBKJI="))
        expected = base64.b64decode("9EOKy35w4PyWHccDVn9cpuDa0w6ulCS4aOOutOPy/TE=")
        assert (hashlib.sha256(data).digest() == expected)

        with open("foo.jpg", "wb") as f:
            f.write(data)
