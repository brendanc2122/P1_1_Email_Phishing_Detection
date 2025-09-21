import pandas as pd
import os
import numpy as np
import re
from email import parser

def create_dataframe_from_group(category):
# category: easy_ham, easy_ham_2, hard_ham, spam, spam_2
    path = f'spamassassin_corpus/{category}'

    def get_raw_emails():
        raw_emails = []
        
        try:
            files_list = os.listdir(path)
        except Exception as e:
            print(f"Error reading database {category}: {e}")
            return


        for file_path in files_list:
            if file_path is not None and file_path != "cmds":
                # For some reason some of the datasets have this file called "cmds" that
                # is just leftover commands to move the files to their respective category.
                # It is not an email so I don't read it
                try:
                    with open(f'spamassassin_corpus/{category}/{file_path}', encoding='latin-1') as f:
                        raw_email_content = f.read()
                        raw_emails.append(raw_email_content)
                except FileNotFoundError:
                    print(f"Error: File not found at {file_path}")
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")

        return raw_emails
    
    subjects = []
    senders = []
    bodies = []
    raw_emails_list = get_raw_emails()

    for raw_email_content in raw_emails_list:
        try:
            msg = parser.Parser().parsestr(raw_email_content)
            senders.append(msg['From'])
            subjects.append(msg['Subject'])

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

            bodies.append(body)

        except Exception as e:
            print(f"Error parsing email: {e}")
            senders.append(None)
            subjects.append(None)
            bodies.append(None)
    
    # Create a pandas DataFrame from the email data
    df_emails = pd.DataFrame({
        'sender': senders,
        'subject': subjects,
        'body': bodies
    })

    return df_emails

# Dataframe for spam
spam_df = create_dataframe_from_group('spam')
spam_2_df = create_dataframe_from_group('spam_2')
spam_df_combined = pd.concat([spam_df, spam_2_df], ignore_index=True)

# Sample a few random rows of the DataFrame and its info
print("\nSpam Email Dataframe:")
# print(spam_df_combined.sample(5))
print(spam_df_combined.info())

# Dataframe for easy_ham
easy_ham_df = create_dataframe_from_group('easy_ham')
easy_ham_2_df = create_dataframe_from_group('easy_ham_2')
easy_ham_df_combined = pd.concat([easy_ham_df, easy_ham_2_df], ignore_index=True)

# Sample a few random rows of the DataFrame and its info
print("\nEasy Ham Email Dataframe:")
# print(easy_ham_df_combined.sample(5))
print(easy_ham_df_combined.info())

# Dataframe for hard_ham
hard_ham_df = create_dataframe_from_group('hard_ham')

# Sample a few random rows of the DataFrame and its info
print("\nHard Ham Email Dataframe:")
# print(hard_ham_df.sample(5))
print(hard_ham_df.info())

spam_count = len(spam_df_combined)
easy_ham_count = len(easy_ham_df_combined)
hard_ham_count = len(hard_ham_df)

total_email_count = spam_count + easy_ham_count + hard_ham_count
print((f"\nTotal number of emails: {total_email_count}"
       f"\nNumber of spam emails: {spam_count} ({spam_count/total_email_count*100:.2f}%)")
    )