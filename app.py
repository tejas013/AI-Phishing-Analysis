from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import tldextract
import re
import traceback

# Initialize the Flask application
app = Flask(__name__)
# Enable Cross-Origin Resource Sharing (CORS) to allow your front-end to communicate with this back-end
CORS(app)

# --- Feature Extraction Functions (Heuristics) ---

# 1. URL-Based Features
def check_url_length(url):
    """Checks if the URL length is suspicious."""
    if len(url) > 75:
        return 20  # High risk
    elif len(url) > 50:
        return 10  # Moderate risk
    return 0

def check_for_ip_address(url):
    """Checks if the URL uses an IP address instead of a domain name."""
    # Regex to check for IP address format
    if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url):
        return 30 # High risk
    return 0

def check_suspicious_tld(url):
    """Checks for suspicious Top-Level Domains (TLDs)."""
    suspicious_tlds = ['.xyz', '.top', '.link', '.click', '.live', '.loan', '.gdn']
    ext = tldextract.extract(url)
    if f".{ext.suffix}" in suspicious_tlds:
        return 25 # High risk
    return 0
    
def check_domain_age(url):
    """Checks the age of the domain. Newer domains are more suspicious."""
    try:
        ext = tldextract.extract(url)
        domain_name = f"{ext.domain}.{ext.suffix}"
        domain_info = whois.whois(domain_name)
        
        # Handle cases where creation_date is a list or single value
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age = (datetime.now() - creation_date).days
            if age < 180: # Less than 6 months old
                return 30 # High risk
            elif age < 365: # Less than 1 year old
                return 15 # Moderate risk
    except Exception:
        # If WHOIS lookup fails, we can't determine age, so we assign a moderate penalty
        return 10
    return 0

def check_suspicious_keywords(url):
    """Checks for keywords commonly found in phishing URLs."""
    keywords = ['login', 'secure', 'account', 'verify', 'update', 'signin', 'bank', 'paypal']
    score = 0
    for keyword in keywords:
        if keyword in url.lower():
            score += 5
    return score

# 2. Content-Based Features
def check_form_action(url):
    """Checks if login forms submit to a different domain."""
    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        if not forms:
            return 0

        page_domain = tldextract.extract(url).registered_domain
        for form in forms:
            action = form.get('action', '')
            # Check for empty action (submits to self) or relative paths
            if not action or action.startswith('/'):
                continue
            
            action_domain = tldextract.extract(action).registered_domain
            if action_domain and page_domain not in action_domain:
                return 35 # Very high risk: submitting credentials to a third-party domain
    except requests.RequestException:
        return 10 # Penalize if we can't access the content
    return 0

# --- Main API Endpoint ---
@app.route('/analyze', methods=['POST'])
def analyze_url():
    """Main endpoint to analyze a URL."""
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    # Add http:// if missing for proper parsing
    if not re.match(r'http(s?):', url):
        url = 'http://' + url

    total_score = 0
    details = []

    try:
        # Run all checks and accumulate score
        score_length = check_url_length(url)
        if score_length > 0:
            total_score += score_length
            details.append(f"Suspiciously long URL ({score_length} points)")

        score_ip = check_for_ip_address(url)
        if score_ip > 0:
            total_score += score_ip
            details.append(f"URL uses an IP address ({score_ip} points)")
            
        score_tld = check_suspicious_tld(url)
        if score_tld > 0:
            total_score += score_tld
            details.append(f"Uses a suspicious TLD ({score_tld} points)")

        score_age = check_domain_age(url)
        if score_age > 0:
            total_score += score_age
            details.append(f"Domain is very new ({score_age} points)")

        score_keywords = check_suspicious_keywords(url)
        if score_keywords > 0:
            total_score += score_keywords
            details.append(f"URL contains suspicious keywords ({score_keywords} points)")
            
        score_form = check_form_action(url)
        if score_form > 0:
            total_score += score_form
            details.append(f"Forms may submit data to an external domain ({score_form} points)")

        # Determine final verdict based on total score
        verdict = "Safe"
        if total_score > 70:
            verdict = "Malicious"
        elif total_score > 40:
            verdict = "Suspicious"
        
        # Cap the score at 100 for display
        display_score = min(total_score, 100)

        # Create the final response object
        response_data = {
            'url': url,
            'score': 100 - display_score, # We want a "safety" score, so 100 is good, 0 is bad
            'status': verdict,
            'details': "Key findings: " + ", ".join(details) if details else "No major risk factors detected by our analysis."
        }
        return jsonify(response_data)

    except Exception as e:
        print(traceback.format_exc()) # Print detailed error to your console for debugging
        return jsonify({'error': 'An error occurred during analysis.'}), 500

# To run the app
if __name__ == '__main__':
    # Runs the server on http://127.0.0.1:5000
    app.run(debug=True, port=5000)