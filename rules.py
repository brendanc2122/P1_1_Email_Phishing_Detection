class Rule:
    def __init__(self):
        # Initialize any attributes here
        self.subject = ''  # Example attribute
        self.sender = ''  # Example attribute
        self.body = ''    # Example attribute
        # If you want any any other attributes, add them here

    # Add methods for your rules here
    def example_rule_1(self):
        # Example rule logic
        # return "phishing" in email_text.lower()
        print('hello')
        return

    def example_rule_2(self, header, sender, body):
        # Example rule logic
        # return "phishing" in email_text.lower()
        pass

    def example_rule_3(self, header, sender, body):
        # Example rule logic
        # return "phishing" in email_text.lower()
        pass

    # Etc.

# Allow this file to be imported without running any code

__all__ = ['Rule']