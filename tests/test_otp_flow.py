import unittest
import os
from unittest.mock import patch

os.environ.setdefault("SECRET_KEY", "test-secret-key")

from app import app, get_db, init_db


class OtpFlowTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True
        app.config["WTF_CSRF_ENABLED"] = False
        with app.app_context():
            init_db()
            db = get_db()
            db.execute(
                "UPDATE users SET email = ?, status = 'Active' WHERE username = ?",
                ("admin@example.com", "admin"),
            )
            db.commit()

    def _set_otp_session(self, code="123456", expiry="2999-01-01T00:00:00", attempts=0):
        with self.client.session_transaction() as sess:
            sess["otp_code"] = code
            sess["otp_expiry"] = expiry
            sess["otp_attempts"] = attempts
            sess["otp_username"] = "admin"
            sess["otp_role"] = "admin"
            sess["otp_email"] = "admin@example.com"
            sess["otp_next"] = "/admin"
            sess["otp_purpose"] = "admin_login"

    def test_correct_otp(self):
        self._set_otp_session()
        response = self.client.post("/verify-otp", data={"otp": "123456"}, follow_redirects=False)
        self.assertIn(response.status_code, (301, 302))

    def test_incorrect_otp(self):
        self._set_otp_session()
        response = self.client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Incorrect OTP", response.data)

    def test_expired_otp(self):
        self._set_otp_session(expiry="2000-01-01T00:00:00")
        response = self.client.post("/verify-otp", data={"otp": "123456"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"OTP expired", response.data)

    def test_multiple_attempts_locks_flow(self):
        self._set_otp_session(attempts=3)
        response = self.client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Too many OTP attempts", response.data)

    @patch("app.issue_otp_challenge")
    def test_resend_otp(self, mock_issue):
        mock_issue.return_value = True
        self._set_otp_session()
        response = self.client.post("/resend-otp", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_issue.called)

    @patch("app.issue_otp_challenge")
    def test_rate_limit_exceeded(self, mock_issue):
        mock_issue.return_value = False
        with self.client.session_transaction() as sess:
            sess["otp_username"] = "admin"
            sess["otp_next"] = "/admin"
        response = self.client.post("/resend-otp", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_issue.called)


if __name__ == "__main__":
    unittest.main()
