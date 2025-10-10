import os
import time
import pandas as pd
from preprocess_dataset import DatasetPreprocessor
from main import PhishingDetector

if __name__ == "__main__":
    dataset_folder = "spamassassin_corpus"
    start_time = time.perf_counter() # Record time taken to show performance

    # Easy ham e-mails
    file_easyham = os.listdir('spamassassin_corpus/easy_ham')
    file_easyham2 = os.listdir('spamassassin_corpus/easy_ham_2')
    
    # Hard ham e-mails
    file_hardham = os.listdir('spamassassin_corpus/hard_ham')

    # Spam e-mails
    file_spam = os.listdir('spamassassin_corpus/spam')
    file_spam2 = os.listdir('spamassassin_corpus/spam_2')
    
    # Create easy dataframes and then combine
    easy1_df = (DatasetPreprocessor(file_easyham, 'spamassassin_corpus/easy_ham')
                          .preprocess_data())
    easy2_df = (DatasetPreprocessor(file_easyham2, 'spamassassin_corpus/easy_ham_2')
                          .preprocess_data())
    easy_df_combined = pd.concat([easy1_df, easy2_df], ignore_index=True)
    
    hard_df = (DatasetPreprocessor(file_hardham, 'spamassassin_corpus/hard_ham')
                          .preprocess_data())
    
    spam1_df = (DatasetPreprocessor(file_spam, 'spamassassin_corpus/spam')
                          .preprocess_data())
    spam2_df = (DatasetPreprocessor(file_spam2, 'spamassassin_corpus/spam_2')
                          .preprocess_data())
    spam_df_combined = pd.concat([spam1_df, spam2_df], ignore_index=True)

    # Take 100 random e-mails from each dataframe for demonstration purposes
    easy_100 = easy_df_combined.sample(n=100, random_state=1)
    hard_100 = hard_df.sample(n=100, random_state=1)
    spam_100 = spam_df_combined.sample(n=100, random_state=1)

    # Test on main Phishing Detector
    results_spam = PhishingDetector(spam_100).only_return_points()
    results_easy = PhishingDetector(easy_100).only_return_points()
    results_hard = PhishingDetector(hard_100).only_return_points()

    avg_results_spam = sum(results_spam) / len(results_spam)
    avg_results_easy = sum(results_easy) / len(results_easy)
    avg_results_hard = sum(results_hard) / len(results_hard)
    
    end_time = time.perf_counter()
    time_taken = end_time - start_time

    print(f"Program finished. Total execution time: {time_taken:.4f}s")
    print("Average Phishing score of 100 spam emails: ", avg_results_spam)
    print("Average Phishing score for 100 easy-ham emails: ", avg_results_easy)
    print("Average Phishing score for 100 hard-ham emails: ", avg_results_hard)