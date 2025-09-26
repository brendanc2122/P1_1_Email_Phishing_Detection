# import re
# from typing import Dict, List, Tuple

# def detect_phishing_buzzwords(subject: str, body: str) -> Dict:
#     """
#     Detects phishing buzzwords in email subject and body.
    
#     Args:
#         subject (str): Email subject line
#         body (str): Email body content
        
#     Returns:
#         dict: Contains total score, breakdown by category, and matched words
#     """
    
#     # Define buzzword categories with weights
#     buzzword_categories = {
#         'urgency': {
#             'weight': 3,
#             'words': [
#                 'urgent', 'immediate', 'asap', 'emergency', 'critical', 'deadline',
#                 'expires', 'expiring', 'time sensitive', 'act now', 'limited time',
#                 'hurry', 'rush', 'quickly', 'fast', 'instant', 'today only',
#                 'last chance', 'final notice', 'don\'t wait', 'time is running out'
#             ]
#         },
#         'financial_threats': {
#             'weight': 4,
#             'words': [
#                 'suspended', 'blocked', 'frozen', 'locked', 'compromised', 'breach',
#                 'unauthorized', 'fraudulent', 'illegal', 'violation', 'penalty',
#                 'fine', 'fee', 'charge', 'payment failed', 'declined', 'overdue',
#                 'debt', 'owe', 'collection', 'lawsuit', 'legal action', 'court',
#                 'seizure', 'garnishment', 'bankruptcy', 'credit score'
#             ]
#         },
#         'reward_baits': {
#             'weight': 3,
#             'words': [
#                 'winner', 'congratulations', 'prize', 'reward', 'bonus', 'gift',
#                 'free', 'complimentary', 'voucher', 'coupon', 'discount',
#                 'cashback', 'refund', 'rebate', 'lottery', 'sweepstakes',
#                 'contest', 'promotion', 'offer', 'deal', 'savings', 'win',
#                 'jackpot', 'million', 'thousand', 'inheritance', 'beneficiary'
#             ]
#         },
#         'trust_exploitation': {
#             'weight': 4,
#             'words': [
#                 'verify', 'confirm', 'validate', 'authenticate', 'update',
#                 'renew', 'reactivate', 'restore', 'secure', 'protect',
#                 'security alert', 'account alert', 'login attempt', 'suspicious',
#                 'unusual activity', 'maintenance', 'system update', 'upgrade',
#                 'notification', 'warning', 'alert', 'notice', 'important'
#             ]
#         },
#         'action_demands': {
#             'weight': 3,
#             'words': [
#                 'click here', 'download', 'install', 'open attachment', 'reply',
#                 'call now', 'contact us', 'respond', 'submit', 'provide',
#                 'enter', 'input', 'fill out', 'complete', 'sign in', 'log in',
#                 'access', 'visit', 'go to', 'follow link', 'activate',
#                 'enable', 'disable', 'cancel', 'unsubscribe', 'opt out'
#             ]
#         },
#         'personal_info_requests': {
#             'weight': 5,
#             'words': [
#                 'ssn', 'social security', 'password', 'pin', 'username',
#                 'account number', 'routing number', 'credit card', 'debit card',
#                 'cvv', 'security code', 'date of birth', 'mother\'s maiden name',
#                 'personal information', 'sensitive data', 'confidential',
#                 'private', 'credentials', 'login details', 'banking info',
#                 'financial information', 'identity', 'verification code'
#             ]
#         },
#         'impersonation': {
#             'weight': 4,
#             'words': [
#                 'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
#                 'facebook', 'netflix', 'ebay', 'irs', 'fbi', 'police',
#                 'government', 'federal', 'department', 'agency', 'official',
#                 'administration', 'bureau', 'service', 'support team',
#                 'customer service', 'security team', 'it department',
#                 'help desk', 'technical support', 'billing department'
#             ]
#         },
#         'emotional_manipulation': {
#             'weight': 3,
#             'words': [
#                 'worried', 'concerned', 'afraid', 'scared', 'panic', 'fear',
#                 'disaster', 'catastrophe', 'terrible', 'awful', 'horrible',
#                 'shocking', 'unbelievable', 'devastating', 'tragic', 'crisis',
#                 'emergency situation', 'dire', 'serious', 'grave', 'alarming',
#                 'disturbing', 'frightening', 'threatening', 'dangerous'
#             ]
#         },
#         'technical_scare': {
#             'weight': 3,
#             'words': [
#                 'virus', 'malware', 'trojan', 'infected', 'hacked', 'hacker',
#                 'cyber attack', 'data breach', 'security breach', 'vulnerability',
#                 'exploit', 'phishing', 'spam', 'scam', 'ransomware',
#                 'keylogger', 'spyware', 'corrupted', 'damaged', 'error',
#                 'system failure', 'crashed', 'broken', 'malfunctioning'
#             ]
#         },
#         'generic_greetings': {
#             'weight': 2,
#             'words': [
#                 'dear customer', 'dear user', 'dear member', 'dear sir/madam',
#                 'valued customer', 'account holder', 'subscriber', 'client',
#                 'user', 'member', 'customer', 'dear friend', 'hello there',
#                 'greetings', 'attention', 'notice to', 'important message for'
#             ]
#         },
#         'poor_grammar_indicators': {
#             'weight': 1,
#             'words': [
#                 'kindly', 'please kindly', 'do needful', 'revert back',
#                 'prepone', 'good day', 'compliments of the day',
#                 'how do you do', 'i hope this meets you well',
#                 'i hope you are fine', 'thanks for your cooperation'
#             ]
#         }
#     }
    
#     # Convert inputs to lowercase for case-insensitive matching
#     subject_lower = subject.lower()
#     body_lower = body.lower()
    
#     # Initialize results
#     total_score = 0
#     category_scores = {}
#     matched_words = {}
#     all_matches = []
#     subject_multiplier = 1.1  # 10% higher scoring for subject buzzwords
    
#     # Check each category for both subject and body
#     for category, data in buzzword_categories.items():
#         category_matches = []
#         category_score = 0
        
#         for word in data['words']:
#             # Use word boundary regex for better matching
#             pattern = r'\b' + re.escape(word.lower()) + r'\b'
            
#             # Check subject matches (with 1.1x multiplier)
#             subject_matches = re.findall(pattern, subject_lower)
#             if subject_matches:
#                 subject_count = len(subject_matches)
#                 subject_score = subject_count * data['weight'] * subject_multiplier
#                 category_score += subject_score
#                 category_matches.extend([f"{word} (subject)"] * subject_count)
#                 all_matches.extend([f"{word} (subject x{subject_count})"])
            
#             # Check body matches (normal scoring)
#             body_matches = re.findall(pattern, body_lower)
#             if body_matches:
#                 body_count = len(body_matches)
#                 body_score = body_count * data['weight']
#                 category_score += body_score
#                 category_matches.extend([f"{word} (body)"] * body_count)
#                 all_matches.extend([f"{word} (body x{body_count})"])
        
#         # Only add to results if matches found
#         if category_matches:
#             matched_words[category] = category_matches
#             category_scores[category] = round(category_score, 2)
#             total_score += category_score
    
#     # Calculate additional risk factors
#     risk_factors = []
#     combined_text = f"{subject_lower} {body_lower}"  # Only for additional checks
    
#     # Check for suspicious URLs/domains
#     suspicious_domains = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short.link']
#     url_pattern = r'https?://(?:www\.)?([^/\s]+)'
#     urls = re.findall(url_pattern, combined_text)
    
#     for url in urls:
#         for domain in suspicious_domains:
#             if domain in url:
#                 risk_factors.append(f"Suspicious shortened URL: {url}")
#                 total_score += 2
    
#     # Check for multiple exclamation marks or all caps
#     if re.search(r'!!!+', combined_text):
#         risk_factors.append("Multiple exclamation marks detected")
#         total_score += 1
    
#     caps_words = re.findall(r'\b[A-Z]{3,}\b', subject + " " + body)
#     if len(caps_words) > 2:
#         risk_factors.append(f"Excessive capitalization: {len(caps_words)} words in all caps")
#         total_score += len(caps_words) * 0.5
    
#     # Check for suspicious email patterns
#     if re.search(r'\b\d{4}-\d{4}-\d{4}-\d{4}\b', combined_text):
#         risk_factors.append("Potential credit card number pattern")
#         total_score += 5
    
#     # Determine risk level
#     if total_score >= 20:
#         risk_level = "HIGH RISK"
#     elif total_score >= 10:
#         risk_level = "MEDIUM RISK"
#     elif total_score >= 5:
#         risk_level = "LOW RISK"
#     else:
#         risk_level = "MINIMAL RISK"
    
#     return {
#         'total_score': round(total_score, 2),
#         'risk_level': risk_level,
#         'category_scores': category_scores,
#         'matched_words': matched_words,
#         'all_matches': all_matches,
#         'risk_factors': risk_factors,
#         'word_count': len((subject + " " + body).split()),
#         'match_density': round((len(all_matches) / len((subject + " " + body).split())) * 100, 2) if (subject + " " + body).split() else 0,
#         'subject_multiplier': subject_multiplier
#     }

# def print_detailed_report(subject: str, body: str):
#     """
#     Prints a detailed analysis report of the phishing detection results.
#     """
#     result = detect_phishing_buzzwords(subject, body)
    
#     print("="*60)
#     print("PHISHING EMAIL ANALYSIS REPORT")
#     print("="*60)
#     print(f"Subject: {subject}")
#     print(f"Body Preview: {body[:100]}{'...' if len(body) > 100 else ''}")
#     print("-"*60)
#     print(f"RISK LEVEL: {result['risk_level']}")
#     print(f"Subject Multiplier: {result['subject_multiplier']}x")
#     print(f"Total Score: {result['total_score']}")
#     print(f"Match Density: {result['match_density']}%")
#     print("-"*60)
    
#     if result['category_scores']:
#         print("CATEGORY BREAKDOWN:")
#         for category, score in sorted(result['category_scores'].items(), 
#                                     key=lambda x: x[1], reverse=True):
#             print(f"  {category.replace('_', ' ').title()}: {score}")
#             if category in result['matched_words']:
#                 words = result['matched_words'][category]
#                 unique_words = list(set(words))
#                 print(f"    Matched: {', '.join(unique_words[:5])}" + 
#                       (f" (+{len(unique_words)-5} more)" if len(unique_words) > 5 else ""))
#         print()
    
#     if result['risk_factors']:
#         print("ADDITIONAL RISK FACTORS:")
#         for factor in result['risk_factors']:
#             print(f"  • {factor}")
    
#     print("="*60)

# # Example usage and testing
# if __name__ == "__main__":
#     # Test with a suspicious email
#     test_subject = "URGENT: Your Account Will Be SUSPENDED - Verify NOW!"
#     test_body = """
#     Dear Customer,
    
#     Your PayPal account has been compromised and will be suspended immediately if you don't act now!
    
#     Unusual activity detected on your account. Click here to verify your identity and prevent account closure.
    
#     You must provide your password, SSN, and credit card information to restore access.
    
#     This is your final warning - don't wait!
    
#     Click here: http://bit.ly/paypal-verify-now
    
#     PayPal Security Team
#     """
    
#     # print_detailed_report(test_subject, test_body)
    
#     # print("\n" + "="*60)
#     # print("SIMPLE SCORING EXAMPLE:")
#     # print("="*60)
    
#     # Simple example
#     result = detect_phishing_buzzwords(test_subject, test_body)
#     print(f"Score: {result['total_score']} - {result['risk_level']}")
#     #print(f"Found {len(result['all_matches'])} suspicious terms")
import re
import hashlib
from typing import Dict, List, Tuple, Set
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
import json

class PhishingDetector:
    def __init__(self):
        # Precompile regex patterns for better performance
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.url_pattern = re.compile(r'https?://[^\s<>"]+', re.IGNORECASE)
        
        # Precompiled suspicious patterns
        self.suspicious_patterns = [
            (re.compile(r'secure.*update', re.IGNORECASE), "Contains 'secure update' pattern"),
            (re.compile(r'verify.*account', re.IGNORECASE), "Contains 'verify account' pattern"), 
            (re.compile(r'login.*now', re.IGNORECASE), "Contains 'login now' pattern"),
            (re.compile(r'suspended.*account', re.IGNORECASE), "Contains 'suspended account' pattern"),
            (re.compile(r'urgent.*action', re.IGNORECASE), "Contains 'urgent action' pattern")
        ]
        
        # Use sets for O(1) lookups instead of lists
        self.safe_domains = set()
        self.suspicious_domains = set()
        
        # Cache for domain analysis results
        self.domain_cache = {}
        
        # Enhanced buzzword categories with compiled patterns
        self.buzzword_categories = self._compile_buzzword_patterns()
        
        # Common legitimate domains (can be loaded from config)
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'ebay.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'github.com', 'stackoverflow.com'
        }

    def _compile_buzzword_patterns(self) -> Dict:
        """Precompile buzzword patterns for better performance"""
        categories = {
            'urgency': {
                'weight': 3,
                'words': [
                    'urgent', 'immediate', 'asap', 'emergency', 'critical', 'deadline',
                    'expires', 'expiring', 'time sensitive', 'act now', 'limited time',
                    'hurry', 'rush', 'quickly', 'fast', 'instant', 'today only',
                    'last chance', 'final notice', 'don\'t wait', 'time is running out'
                ]
            },
            'financial_threats': {
                'weight': 4,
                'words': [
                    'suspended', 'blocked', 'frozen', 'locked', 'compromised', 'breach',
                    'unauthorized', 'fraudulent', 'illegal', 'violation', 'penalty',
                    'fine', 'fee', 'charge', 'payment failed', 'declined', 'overdue',
                    'debt', 'owe', 'collection', 'lawsuit', 'legal action', 'court',
                    'seizure', 'garnishment', 'bankruptcy'
                ]
            },
            'social_engineering': {
                'weight': 3.5,
                'words': [
                    'verify', 'confirm', 'update', 'validate', 'authenticate',
                    'click here', 'download now', 'open attachment', 'free gift',
                    'congratulations', 'winner', 'selected', 'exclusive offer',
                    'limited offer', 'act fast', 'don\'t miss out'
                ]
            },
            'impersonation': {
                'weight': 4.5,
                'words': [
                    'security team', 'support team', 'account team', 'fraud department',
                    'billing department', 'customer service', 'technical support',
                    'system administrator', 'it department', 'security alert'
                ]
            }
        }
        
        # Compile patterns for each category
        for category, data in categories.items():
            patterns = []
            for word in data['words']:
                patterns.append(re.compile(r'\b' + re.escape(word) + r'\b', re.IGNORECASE))
            data['patterns'] = patterns
            
        return categories

    def load_domain_lists(self, suspicious_domains: List[str], safe_domains: List[str]):
        """Load and cache domain lists"""
        self.suspicious_domains = set(domain.lower() for domain in suspicious_domains)
        self.safe_domains = set(domain.lower() for domain in safe_domains)

    def extract_domain(self, url: str) -> str:
        """Extract domain from URL with better parsing"""
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            return parsed.netloc.lower()
        except:
            return url.lower()

    def analyze_url_risk(self, url: str, is_subject: bool = False) -> Tuple[float, List[str]]:
        """
        Enhanced URL risk analysis with caching and better domain detection
        """
        # Create cache key
        cache_key = hashlib.md5(f"{url}_{is_subject}".encode()).hexdigest()
        if cache_key in self.domain_cache:
            return self.domain_cache[cache_key]
        
        multiplier = 1.1 if is_subject else 1.0
        risk_score = 0
        risk_reasons = []
        
        url_lower = url.lower()
        domain = self.extract_domain(url)
        
        # Check if it's a trusted domain first
        if any(trusted in domain for trusted in self.trusted_domains):
            result = (0, ["Trusted domain - no risk"])
            self.domain_cache[cache_key] = result
            return result
        
        # Check against safe domains
        if any(safe_domain in url_lower for safe_domain in self.safe_domains):
            result = (0, ["Safe domain - no risk"])
            self.domain_cache[cache_key] = result
            return result
        
        # Check against suspicious domains
        for sus_domain in self.suspicious_domains:
            if sus_domain in url_lower:
                risk_score += 3 * multiplier
                risk_reasons.append(f"Known suspicious domain: {sus_domain}")
                break
        
        # Check for IP addresses (more precise regex)
        if self.ip_pattern.search(url):
            risk_score += 4 * multiplier
            risk_reasons.append("Uses IP address instead of domain name")
        
        # Enhanced subdomain analysis
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            risk_score += 2 * multiplier
            risk_reasons.append(f"Too many subdomains ({subdomain_count})")
        
        # Check for suspicious URL patterns (using precompiled regex)
        for pattern, description in self.suspicious_patterns:
            if pattern.search(url):
                risk_score += 2 * multiplier
                risk_reasons.append(description)
        
        # Enhanced URL length analysis (adaptive threshold)
        if len(url) > 150:
            risk_score += 2 * multiplier
            risk_reasons.append("Extremely long URL")
        elif len(url) > 75:
            risk_score += 1 * multiplier
            risk_reasons.append("Unusually long URL")
        
        # Check for multiple hyphens in domain only
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            risk_score += 1.5 * multiplier
            risk_reasons.append(f"Too many hyphens in domain ({hyphen_count})")
        
        # Check for homograph attacks (similar looking domains)
        if self._check_homograph_attack(domain):
            risk_score += 3 * multiplier
            risk_reasons.append("Potential homograph attack")
        
        # Check for URL shorteners
        if self._is_url_shortener(domain):
            risk_score += 1.5 * multiplier
            risk_reasons.append("Uses URL shortener")
        
        result = (round(risk_score, 2), risk_reasons)
        self.domain_cache[cache_key] = result
        return result

    def _check_homograph_attack(self, domain: str) -> bool:
        """Check for potential homograph attacks"""
        suspicious_chars = ['а', 'о', 'р', 'е', 'х', 'у', 'с', 'н', 'к', 'і']  # Cyrillic lookalikes
        return any(char in domain for char in suspicious_chars)

    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a known URL shortener"""
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'}
        return domain in shorteners

    def analyze_text_patterns(self, text: str, weight_multiplier: float = 1.0) -> Tuple[float, List[str]]:
        """Analyze text for phishing patterns using precompiled regex"""
        score = 0
        detected_patterns = []
        text_lower = text.lower()
        
        for category_name, category_data in self.buzzword_categories.items():
            category_matches = 0
            for pattern in category_data['patterns']:
                if pattern.search(text):
                    category_matches += 1
            
            if category_matches > 0:
                category_score = category_matches * category_data['weight'] * weight_multiplier
                score += category_score
                detected_patterns.append(f"{category_name}: {category_matches} matches")
        
        return score, detected_patterns

    def detect_phishing_comprehensive(self, subject: str, body: str, 
                                    sender_email: str = "", 
                                    urls: List[str] = None) -> Dict:
        """
        Comprehensive phishing detection with multiple analysis layers
        """
        if urls is None:
            # Extract URLs from subject and body
            urls = self.url_pattern.findall(subject + " " + body)
        
        analysis_start = datetime.now()
        
        # Analyze subject (higher weight)
        subject_score, subject_patterns = self.analyze_text_patterns(subject, 1.2)
        
        # Analyze body
        body_score, body_patterns = self.analyze_text_patterns(body, 1.0)
        
        # Analyze URLs
        url_scores = []
        url_risks = []
        total_url_risk = 0
        
        for i, url in enumerate(urls):
            is_in_subject = url in subject
            url_risk, url_reasons = self.analyze_url_risk(url, is_in_subject)
            url_scores.append(url_risk)
            url_risks.extend(url_reasons)
            total_url_risk += url_risk
        
        # Sender analysis
        sender_risk = self._analyze_sender(sender_email)
        
        # Calculate composite risk score
        total_score = subject_score + body_score + total_url_risk + sender_risk
        
        # Determine risk level
        if total_score >= 10:
            risk_level = "CRITICAL"
        elif total_score >= 6:
            risk_level = "HIGH"
        elif total_score >= 3:
            risk_level = "MEDIUM"
        elif total_score >= 1:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"
        
        processing_time = (datetime.now() - analysis_start).total_seconds()
        
        return {
            'total_risk_score': round(total_score, 2),
            'risk_level': risk_level,
            'subject_analysis': {
                'score': round(subject_score, 2),
                'patterns': subject_patterns
            },
            'body_analysis': {
                'score': round(body_score, 2),
                'patterns': body_patterns
            },
            'url_analysis': {
                'total_score': round(total_url_risk, 2),
                'individual_urls': [
                    {'url': url, 'score': score} for url, score in zip(urls, url_scores)
                ],
                'risks': url_risks
            },
            'sender_analysis': {
                'score': sender_risk,
                'domain': self.extract_domain(sender_email) if '@' in sender_email else 'unknown'
            },
            'processing_time_ms': round(processing_time * 1000, 2),
            'recommendations': self._generate_recommendations(total_score, risk_level)
        }

    def _analyze_sender(self, sender_email: str) -> float:
        """Analyze sender email for suspicious patterns"""
        if not sender_email or '@' not in sender_email:
            return 1.0  # Unknown sender gets small penalty
        
        domain = sender_email.split('@')[1].lower()
        
        # Check against trusted domains
        if any(trusted in domain for trusted in self.trusted_domains):
            return 0
        
        # Check for suspicious patterns in sender
        risk_score = 0
        
        # Check for suspicious domain patterns
        if re.search(r'\d{3,}', domain):  # Many numbers in domain
            risk_score += 1.5
        
        if domain.count('-') > 2:  # Many hyphens
            risk_score += 1.0
        
        if len(domain.split('.')) > 3:  # Too many subdomains
            risk_score += 1.0
        
        return risk_score

    def _generate_recommendations(self, score: float, risk_level: str) -> List[str]:
        """Generate actionable recommendations based on risk level"""
        recommendations = []
        
        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.extend([
                "DO NOT click any links or download attachments",
                "Report this email as phishing to your IT security team",
                "Delete the email immediately",
                "If you've already clicked links, change your passwords immediately"
            ])
        elif risk_level == "MEDIUM":
            recommendations.extend([
                "Exercise caution - verify sender through alternative means",
                "Do not provide sensitive information",
                "Check URLs carefully before clicking"
            ])
        elif risk_level == "LOW":
            recommendations.append("Low risk but remain vigilant")
        
        return recommendations

    def batch_analyze(self, emails: List[Dict]) -> List[Dict]:
        """Efficiently analyze multiple emails"""
        results = []
        for email in emails:
            result = self.detect_phishing_comprehensive(
                email.get('subject', ''),
                email.get('body', ''),
                email.get('sender', ''),
                email.get('urls', [])
            )
            result['email_id'] = email.get('id', len(results))
            results.append(result)
        
        return results

    def clear_cache(self):
        """Clear the domain analysis cache"""
        self.domain_cache.clear()


# Example usage and testing
def main():
    detector = PhishingDetector()
    
    # Load domain lists (these would typically come from threat intelligence feeds)
    suspicious_domains = ["phishing-site.com", "fake-bank.net", "suspicious.org"]
    safe_domains = ["legitimate-bank.com", "trusted-site.org"]
    detector.load_domain_lists(suspicious_domains, safe_domains)
    
    # Test email
    test_subject = "URGENT: Your account will be suspended - Act now!"
    test_body = """
    Dear Customer,
    
    Your account has been compromised and will be suspended unless you verify immediately.
    Click here to login: http://fake-bank.net/login-verify-urgent
    
    This is time sensitive - act within 24 hours or face legal action.
    
    Security Team
    """
    test_sender = "security@fak3-bank.com"
    
    result = detector.detect_phishing_comprehensive(test_subject, test_body, test_sender)
    
    print("Phishing Detection Results:")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Total Score: {result['total_risk_score']}")
    print(f"Processing Time: {result['processing_time_ms']}ms")
    print("\nRecommendations:")
    for rec in result['recommendations']:
        print(f"- {rec}")

if __name__ == "__main__":
    main()