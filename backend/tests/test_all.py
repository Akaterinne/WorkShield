import unittest
from backend.avl import AVLTree
from backend.workshield import WorkShieldSystem
from backend.models import User, Incident


class TestAVL(unittest.TestCase):

    def test_insert_and_search(self):
        tree = AVLTree()
        tree.insert(10, "A")
        tree.insert(5, "B")
        tree.insert(15, "C")

        self.assertEqual(tree.search(10).obj, "A")
        self.assertEqual(tree.search(5).obj, "B")
        self.assertEqual(tree.search(15).obj, "C")

    def test_duplicate_insert(self):
        tree = AVLTree()
        tree.insert(10, "A")
        tree.insert(10, "B")  # should replace
        self.assertEqual(tree.search(10).obj, "B")

    def test_balance_lr(self):
        tree = AVLTree()
        tree.insert(30, "A")
        tree.insert(10, "B")
        tree.insert(20, "C")  # triggers LR rotation
        self.assertIsNotNone(tree.search(20))

class TestSecurity(unittest.TestCase):

    def test_hash_password(self):
        pw = "Senha123"
        hashed = hash_password(pw)
        self.assertTrue(verify_password(pw, hashed))

class TestWorkShield(unittest.TestCase):

    def test_ingest_message_pii(self):
        ws = WorkShieldSystem()
        ws.signup("ana", "1234")
        token = ws.login("ana", "1234")

        incident = ws.ingest_message(token, "Meu CPF é 123.456.789-10")

        self.assertIsNotNone(incident)
        self.assertIn("CPF", incident.details)

    def test_ingest_message_clean(self):
        ws = WorkShieldSystem()
        ws.signup("ana", "1234")
        token = ws.login("ana", "1234")

        incident = ws.ingest_message(token, "Olá, tudo bem?")

        self.assertIsNone(incident)

if __name__ == "__main__":
    unittest.main()
