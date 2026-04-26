import unittest

from app import app
from security import generate_wallet_address
from validation import validate_amount, validate_password, validate_username, validate_wallet_address


class SecurityFeatureTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_username_validation_success(self):
        valid, _ = validate_username("User123")
        self.assertTrue(valid)

    def test_username_validation_failure(self):
        valid, _ = validate_username("ab")
        self.assertFalse(valid)

    def test_password_validation_failure(self):
        valid, _ = validate_password("weakpass")
        self.assertFalse(valid)

    def test_amount_validation(self):
        valid, _, amount = validate_amount("10.5", 100)
        self.assertTrue(valid)
        self.assertEqual(amount, 10.5)

    def test_wallet_generation_format(self):
        wallet = generate_wallet_address()
        self.assertTrue(wallet.startswith("SW-"))
        self.assertEqual(len(wallet), 15)
        valid, _ = validate_wallet_address(wallet)
        self.assertTrue(valid)

    def test_unauthorized_admin_access(self):
        response = self.client.get("/admin", follow_redirects=False)
        self.assertIn(response.status_code, [301, 302])


if __name__ == "__main__":
    unittest.main()
import unittest

from app import app
from security import generate_wallet_address
from validation import validate_amount, validate_password, validate_username, validate_wallet_address


class SecurityFeatureTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_username_validation_success(self):
        valid, _ = validate_username("User123")
        self.assertTrue(valid)

    def test_username_validation_failure(self):
        valid, _ = validate_username("ab")
        self.assertFalse(valid)

    def test_password_validation_failure(self):
        valid, _ = validate_password("weakpass")
        self.assertFalse(valid)

    def test_amount_validation(self):
        valid, _, amount = validate_amount("10.5", 100)
        self.assertTrue(valid)
        self.assertEqual(amount, 10.5)

    def test_wallet_generation_format(self):
        wallet = generate_wallet_address()
        self.assertTrue(wallet.startswith("SW-"))
        self.assertEqual(len(wallet), 15)
        valid, _ = validate_wallet_address(wallet)
        self.assertTrue(valid)

    def test_unauthorized_admin_access(self):
        response = self.client.get("/admin", follow_redirects=False)
        self.assertIn(response.status_code, [301, 302])


if __name__ == "__main__":
    unittest.main()
