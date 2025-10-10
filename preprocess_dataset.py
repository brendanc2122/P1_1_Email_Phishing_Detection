from ast import pattern
import pandas as pd
import numpy as np
import re
from email import parser

class DatasetPreprocessor:
    def __init__(self, uploaded_files, file_path):
        self.uploaded_files = uploaded_files
        self.file_path = file_path
    
    # Obtain raw emails from component's uploaded files and file path
    def __get_raw_emails__(self):
        raw_emails = []

        for file_name in self.uploaded_files:
            if file_name is not None and file_name != "cmds":
                # For some reason some datasets have a file called "cmds" that
                # is just leftover commands to move the files to their respective category.
                # It is not an email so I don't read it
                try:
                    with open(f'{self.file_path}/{file_name}', encoding='latin-1') as f:
                        raw_email_content = f.read()
                        raw_emails.append(raw_email_content)
                except FileNotFoundError:
                    print(f"Error: File not found at {file_name}")
                except Exception as e:
                    print(f"Error reading file {file_name}: {e}")

        return raw_emails
    
    # Cleans HTML tags and elements from email body
    def __clean_body__(self, body): 
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
    
    # Extract sender, domain, subject and body from raw email content
    def __extract_features__(self, raw_email_content):
        # Parse the raw email content using email.parser module
        msg = parser.Parser().parsestr(raw_email_content)
        # Extract sender name, sender email domain and subject
        subject = msg['Subject'] if msg['Subject'] else ""
        sender_full = msg['From'] if msg['From'] else ""

        # Clean sender and domain
        # Use regex to remove trailing < and > from sender's email address if present
        # At the same time, if < and > are present, extract the email
        # address within them as sender_domain
        address_arrow_pattern = r"<([^>]*)>"
        remove_address_pattern = r"<[^>]*>"
        domain = (re.search(address_arrow_pattern, sender_full).group(1)
                        if sender_full and re.search(address_arrow_pattern, sender_full) else "")
        sender = re.sub(remove_address_pattern, "", sender_full) if sender_full else ""


        # body = self.__clean_body__(msg.get_payload()) if msg.is_multipart() else self.__clean_body__(msg.get_payload())
        return msg, subject, sender, domain
    
    # Extract the email body, handling multipart emails
    def __extract_body__(self, msg):
        # Uses functions from email.parser module
        body = ""

        if msg.is_multipart(): # If the email payload has multiple parts
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
        else: # Not a multipart email
            try:
                body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
            except:
                body = msg.get_payload(decode=True).decode('latin-1', errors='ignore')

        return self.__clean_body__(body)

    def preprocess_data(self):
        # Extract raw emails from uploaded files
        raw_emails_list = self.__get_raw_emails__()

        subjects = []
        senders = []
        domains = []
        bodies = []
        
        for raw_email_content in raw_emails_list:
            try: # Try to parse the email
                msg, subject, sender, domain = self.__extract_features__(raw_email_content)
                
                # Append extracted features to their respective lists
                subjects.append(subject)
                senders.append(sender)
                domains.append(domain)

                body = self.__extract_body__(msg)
                bodies.append(body)

            except Exception as e: # Catch any parsing errors
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

        return df_emails