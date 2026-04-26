import os
import smtplib
import threading
from email.mime.text import MIMEText


class EmailDeliveryError(Exception):
    pass


def _send_security_otp_email_sync(recipient_email: str, otp_code: str) -> None:
    smtp_user = os.environ.get("SMTP_USER", os.environ.get("EMAIL_USER", "")).strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", os.environ.get("EMAIL_PASSWORD", "")).strip()
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587").strip())

    if not smtp_user or not smtp_password:
        raise EmailDeliveryError("SMTP credentials are missing.")

    subject = "SUNGA Wallet Security Code"
    body = (
        "Your verification code is:\n\n"
        f"{otp_code}\n\n"
        "This code expires in 5 minutes.\n\n"
        "If you did not request this code, contact support immediately."
    )
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(smtp_user, smtp_password)
            smtp.sendmail(smtp_user, [recipient_email], msg.as_string())
    except Exception as error:
        raise EmailDeliveryError(str(error)) from error


def send_security_otp_email(recipient_email: str, otp_code: str) -> None:
    _send_security_otp_email_sync(recipient_email, otp_code)


def send_security_otp_email_async(recipient_email: str, otp_code: str) -> threading.Thread:
    worker = threading.Thread(
        target=_send_security_otp_email_sync,
        args=(recipient_email, otp_code),
        daemon=True,
        name="sunga-otp-email",
    )
    worker.start()
    return worker
