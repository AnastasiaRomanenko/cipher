from celery import shared_task
from django.core.mail import EmailMessage


@shared_task(bind=True)
def send_bulk_emails(self, subject, body, user_email):
    try:
        email = EmailMessage(
            subject=subject,
            body=body,
            to=[user_email],
        )
        email.content_subtype = "html"
        email.send()

    except Exception as e:
        print(f"Failed to send to {user_email}: {str(e)}")
