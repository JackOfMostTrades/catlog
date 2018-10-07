from unittest import TestCase

from . import main


class TestMain(TestCase):
    def test_push(self):
        main.main()
