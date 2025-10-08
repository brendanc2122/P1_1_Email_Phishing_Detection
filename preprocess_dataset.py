from ast import pattern
import pandas as pd
import os
import numpy as np
import re
from email import parser

def create_dataframe_from_group(uploaded_files_list):
    path = 'uploads'

    def get_raw_emails():
        raw_emails = []

        for file_name in uploaded_files_list:
            if file_name is not None and file_name != "cmds":
                # For some reason some of the datasets have this file called "cmds" that
                # is just leftover commands to move the files to their respective category.
                # It is not an email so I don't read it
                try:
                    with open(f'{path}/{file_name}', encoding='latin-1') as f:
                        raw_email_content = f.read()
                        raw_emails.append(raw_email_content)
                except FileNotFoundError:
                    print(f"Error: File not found at {file_name}")
                except Exception as e:
                    print(f"Error reading file {file_name}: {e}")

        return raw_emails
    
    def clean_body_2(body):
        # Extract the link from <a href > element
        body = re.sub(r'<a.+href="|">|</a>', "", body, flags=re.IGNORECASE)

        # <br> and <br/> are line break elements, so we replace them with a whitespace for now
        body = re.sub(r"<br/?>", " ", body, flags=re.IGNORECASE)

        # Clear everything else
        body = re.sub(r"<[^>]*>", "", body, flags=re.DOTALL)

        # HTML elements to represent certain characters
        body = re.sub(r"&amp;", "&", body, flags=re.IGNORECASE) # &
        body = re.sub(r"&quot;", "'", body, flags=re.IGNORECASE) # quotes
        body = re.sub(r"&nbsp;", " ", body, flags=re.IGNORECASE) # non-breaking space

        body = re.sub(r"\s{2,}", " ", body) # Clears excess (more than 1) consecutive whitespaces

        return body
    
    subjects = []
    senders = []
    domains = []
    bodies = []
    raw_emails_list = get_raw_emails()

    for raw_email_content in raw_emails_list:
        try:
            msg = parser.Parser().parsestr(raw_email_content)
            # Extract sender name, sender email domain and subject
            # If any of these fields are missing, assign None
            sender = msg['From'] if msg['From'] else ""
            subject = msg['Subject'] if msg['Subject'] else ""

            # Use regex to remove trailing < and > from sender's email address if present
            # At the same time, if < and > are present, extract the email
            # address within them as sender_domain
            address_arrow_pattern = r"<([^>]*)>"
            remove_address_pattern = r"<[^>]*>"
            sender_domain = (re.search(address_arrow_pattern, sender).group(1)
                             if sender and re.search(address_arrow_pattern, sender) else "")
            sender = re.sub(remove_address_pattern, "", sender) if sender else ""

            senders.append(sender)
            domains.append(sender_domain)
            subjects.append(subject)

            # Extract body, handling multipart emails
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ctype = part.get_content_type()
                    cdispo = part.get('Content-Disposition')

                    # Look for plain text parts, skipping attachments
                    if ctype == 'text/plain' and cdispo is None:
                        try:
                            body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                            break # Assuming the first text/plain part is the main body
                        except:
                            body = part.get_payload(decode=True).decode('latin-1', errors='ignore')
                            break
            else:
                # Not a multipart email
                try:
                    body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
                except:
                    body = msg.get_payload(decode=True).decode('latin-1', errors='ignore')

            bodies.append(clean_body_2(body))

        except Exception as e:
            print(f"Error parsing email: {e}")
            senders.append(None)
            domains.append(None)
            subjects.append(None)
            bodies.append(None)
    
    # Create a pandas DataFrame from the email data
    df_emails = pd.DataFrame({
        'sender': senders,
        'domain': domains,
        'subject': subjects,
        'body': bodies
    })

    # Save the pandas DataFrame to a CSV file
    # df_emails.to_csv('csv_files/user_data.csv',mode='w',index=False)

    return df_emails