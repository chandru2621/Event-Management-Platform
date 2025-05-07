from app import app, mail
from flask_mail import Message

def test_email():
    with app.app_context():
        try:
            msg = Message(
                subject="Test Email",
                recipients=["chandrumani260@gmail.com"],  # Your email address
                body="This is a test email from your Event Management Platform."
            )
            mail.send(msg)
            print("Test email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {str(e)}")

if __name__ == "__main__":
    test_email() 