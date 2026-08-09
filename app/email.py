import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()


def send_reset_email(
    to_email: str,
    reset_url: str,
):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(
        os.getenv("SMTP_PORT", "587")
    )
    smtp_username = os.getenv(
        "SMTP_USERNAME"
    )
    smtp_password = os.getenv(
        "SMTP_PASSWORD"
    )
    smtp_from = os.getenv(
        "SMTP_FROM"
    )

    if not all(
        [
            smtp_host,
            smtp_username,
            smtp_password,
            smtp_from,
        ]
    ):
        print(
            "\n[DEV] Password reset URL:"
        )
        print(reset_url)
        print()
        return

    message = EmailMessage()

    message["Subject"] = "Reset your password"
    message["From"] = smtp_from
    message["To"] = to_email

    message.set_content(
        f"""
Hello,

We received a request to reset your password.

Open this link:

{reset_url}

This link will expire soon.

If you did not request this,
you can safely ignore this email.
"""
    )

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
    ) as server:

        server.starttls()

        server.login(
            smtp_username,
            smtp_password,
        )

        server.send_message(message)