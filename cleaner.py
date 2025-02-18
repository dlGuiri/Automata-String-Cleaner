import dns.resolver
import re
import socket
import requests

keywords = ["Buy Now", "Urgent", "Account", "Payment", "Verify",
            "Important", "http://", "Link", "Unsubscribe", "Subscribe"]

userInput = """
From: callcenteer@bdoo.com.ph
"Urgent! Your account has been compromised. Click here to reset your password."
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
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.Timeout:
        return False
    except Exception:
        return False

# Fallback: Check if the domain itself exists
def is_valid_domain(domain):
    try:
        # Try resolving the domain
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

# Fallback: Check if the domain has an active website
def domain_responds(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

# Validate email with multiple checks
def is_valid_email(email):
    domain = email.split('@')[-1]
    
    # Primary check: MX records
    if has_mx_record(domain):
        return True
    
    # Secondary checks: Domain existence or response
    return is_valid_domain(domain) or domain_responds(domain)

# Verify sender identity
def senderVerifier():
    global result
    email = extract_email(userInput)
    if email and is_valid_email(email):
        result += "legit"
        checkKeywords()
    elif attemptsToVerify == 1:
        result += "true"
        checkDomain()
    else:
        result += "false"

# Check for phishing keywords
def checkKeywords():
    global attemptsToVerify
    global result
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