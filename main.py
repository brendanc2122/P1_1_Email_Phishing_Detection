from dataclasses import dataclass
import re
import pandas as pd
from urllib.parse import urlparse
from difflib import SequenceMatcher
import math

# Import rules
import domain_checker_rules as domain_check
import url_buzzwords_rules as buzzword_check

class PhishingDetector:
    def __init__(self, dataframe):
        self.dataframe = dataframe
        self.senders = [row['sender'] for index, row in self.dataframe.iterrows()]
        self.domains = [row['domain'] for index, row in self.dataframe.iterrows()]
        self.subjects = [row['subject'] for index, row in self.dataframe.iterrows()]
        self.bodies = [row['body'] for index, row in self.dataframe.iterrows()]

    def __checkdomains__(self):
        count = 0
        for domain in self.domains:
            count += 1
            domain_pts, domain_reasons = domain_check.calculate_score_domain(domain)
            self.__recorddomainresults__(domain_pts, domain_reasons)

    def __recorddomainresults__(self, domain_pts, domain_reasons):
        self.domain_pts.append(domain_pts)
        self.domain_reasons.append(domain_reasons)

    def __checkbuzzwords__(self):
        count = 0
        for subject, body in zip(self.subjects, self.bodies):
            count += 1
            res = buzzword_check.detect_phishing_comprehensive(subject, body)

            # New API: dict return
            if isinstance(res, dict):
                buzzword_pts = float(res.get("total_risk_score", 0.0))
                buzzword_reasons = (
                    list(res.get("subject_analysis", []))
                    + list(res.get("body_analysis", []))
                    + list(res.get("url_analysis", []))
                )
            else:
                # Back-compat if you flip back to tuple in the future
                buzzword_pts, buzzword_reasons = res

            self.__recordbuzzwordresults__(buzzword_pts, buzzword_reasons)

    def __recordbuzzwordresults__(self, buzzword_pts, buzzword_reasons):
        self.buzzword_pts.append(buzzword_pts)
        self.buzzword_reasons.append(buzzword_reasons)

    def __calculate_risklevel__(self, score):
        if score <= 19:
            return "Safe"
        elif score <= 39:
            return "Low risk"
        elif score <= 59:
            return "Suspicious"
        elif score <= 79:
            return "Likely phishing"
        else:
            return "Phishing"

    def __formatresults__(self, cmd):
        results = []

        all_lengths_same = (
            len(self.domain_pts) == len(self.buzzword_pts) ==
            len(self.senders) == len(self.subjects) == len(self.bodies)
        )
        assert all_lengths_same, "Length of lists are not the same!"
        if cmd == "quick": # Only return scores for comparison with testing dataset
            for i in range(len(self.domain_pts)):
                total_score = self.domain_pts[i] + self.buzzword_pts[i]
                results.append(total_score)
        else:
            for i in range(len(self.domain_pts)):
                total_score = self.domain_pts[i] + self.buzzword_pts[i]
                reasons = self.domain_reasons[i] + self.buzzword_reasons[i]
                results.append({
                    "sender": self.senders[i],
                    "domain": self.domains[i],
                    "subject": self.subjects[i],
                    "body": self.bodies[i],
                    "score": total_score,
                    "reasons": reasons,
                    "risk_level": self.__calculate_risklevel__(total_score)
                })
        return results
    
    def analyse(self):
        self.domain_pts = []
        self.domain_reasons = []
        self.buzzword_pts = []
        self.buzzword_reasons = []

        self.__checkdomains__()
        self.__checkbuzzwords__()
        output = self.__formatresults__()
        return output
    
    def only_return_points(self):
        self.domain_pts = []
        self.domain_reasons = []
        self.buzzword_pts = []
        self.buzzword_reasons = []

        self.__checkdomains__()
        self.__checkbuzzwords__()
        output = self.__formatresults__('quick')
        return output
        