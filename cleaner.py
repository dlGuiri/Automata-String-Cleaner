import dns.resolver
import re

keywords = ["Buy Now", "Urgent", "Account", "Payment", "Verify",
            "Important", "http://", "Link", "Unsubscribe", "Subscribe"]

userInput = """
From: callcenter@bdo.com.ph
"Dear customer, your recent transaction has been successfully processed."
"""
result = ""
attemptsToVerify = 0

# Extract email from input
def extract_email(text):
    match = re.search(r"From:\s*([\w\.-]+@[\w\.-]+\.\w+)", text)
    return match.group(1) if match else None

# Check if the domain has valid MX records
def has_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return bool(mx_records)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
        return False

# Validate email by checking MX records
def is_valid_email(email):
    domain = email.split('@')[-1]
    return has_mx_record(domain)

# Verify sender identity
def senderVerifier():
    global result, attemptsToVerify
    email = extract_email(userInput)
    if email and is_valid_email(email) and attemptsToVerify == 0:
        result += "legit"
        checkKeywords()
    elif attemptsToVerify == 1:
        result += "true"
        checkDomain()
    else:
        result += "false"

# Check for phishing keywords
def checkKeywords():
    global attemptsToVerify, result
    for phishingWord in keywords:
        if phishingWord in userInput:
            if attemptsToVerify == 0:
                attemptsToVerify += 1
                result += ''.join(phishingWord.lower().split())
                senderVerifier()
    if attemptsToVerify == 0:
        result += "link"

# Check for suspicious links
def checkDomain():
    global result
    if "https://" in userInput:
        result += "https://"
    elif "http://" in userInput:
        result += "http://"

# Run validation
senderVerifier()
print(result)