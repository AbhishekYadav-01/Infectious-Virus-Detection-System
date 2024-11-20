import smtplib
from email.mime.text import MIMEText
import sys

def send_email(virus_name, folder_path, virus_hash):
    # Configure email
    sender_email = "csgoalternate110@gmail.com"
    sender_password = "tkogdyqcxthhpfcz"  # App-specific password
    recipient_email = "b22es010@iitj.ac.in"

    subject = f"Virus Alert: {virus_name}"
    body = f"""
    Virus Name: {virus_name}
    Folder Path: {folder_path}
    Virus Hash: {virus_hash}

    Please take immediate action to quarantine or delete the affected files.
    """

    # Create email message
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    try:
        # Connect to Gmail's SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade to secure connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Entry point for the script
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: send_email.py <virus_name> <folder_path> <virus_hash>")
        sys.exit(1)

    virus_name = sys.argv[1]
    folder_path = sys.argv[2]
    virus_hash = sys.argv[3]

    send_email(virus_name, folder_path, virus_hash)
