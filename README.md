# P1_1_Email_Phishing_Detection

## 📌 Project Overview
A **rule-based phishing detection system** that verifies the legitimacy of emails by analyzing user-provided inputs:

- **Sender’s Email**
- **Subject Line**
- **Message Body**

This project is a rule-based phishing detection system designed to help users verify the legitimacy of emails. By analyzing structured user inputs (sender email, subject line, and message body), the system applies a set of rules to detect suspicious patterns and classify emails as safe or potentially phishing.

Developed as part of the **INF1002 Programming Fundamentals Module**.


---

## 👥 Team Members
- Aruna Presanna Dhevakash 
- Brejesh Gunasekaran   
- Brendan Chan Wei Jian  
- Sreekantom Sai Saketh  
- Tay Rui Feng 

---

## ⚙️ System Architecture
- **Frontend**:  
  - Built with **HTML** + **Bootstrap/Tailwind CSS**  
  - Structured input fields for sender, subject, and content  
  - Displays results with highlighted suspicious factors  

- **Backend**:  
  - Implemented in **Python (Flask)**  
  - Preprocessing & normalization of inputs  
  - Rule-based detection and scoring system  
  - API to send classification results back to frontend  

---

## ✨ Core Features
- ✅ Rule-based phishing detection:
  - Urgent or threatening language detection  
  - Repeated buzzwords detection  
  - Keyword position weighting (subject > body)  
  - Suspicious/misspelled domain detection  
  - Shortened/unsafe links identification  
  - Image-heavy content detection *(planned)*  

- ✅ **Suspicion Index (SI) Score** for classification  
- ✅ Clear reporting of triggered rules  
- ✅ Dataset support for testing and refinement  

---

## 📂 Dataset
We use the **[SpamAssassin Public Mail Corpus](https://spamassassin.apache.org/)**:

- `spam`: 500 emails  
- `spam_2`: 1397 emails  
- `easy_ham`: 2500 emails  
- `easy_ham_2`: 1400 emails  
- `hard_ham`: 250 emails  

**Total**: 6047 emails (~31.3% spam)

---

