import os
import time
import pandas as pd
import numpy as np
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
    
    # Create dataframes and then combine for categories with two folders
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

    # Function to reduce repitition
    def create_dataset_statistics(df, category):
        # Sample 100 random emails from the dataframe, random state to ensure reproductivity of results
        df_100 = df.sample(n=100,random_state=34)

        # Only return total phishing score and sort by ascending score.
        results = sorted(PhishingDetector(df_100).only_return_points())
        
        # Stats to be printed out
        results_mean = sum(results) / len(results)
        results_median = (results[49]+results[50])//2
        results_std = np.std(results)
        results_range = max(results) - min(results)

        data = {'Category': [category],
                'Mean': [results_mean],
                'Median': [results_median],
                'Standard deviation': [results_std],
                'Range': [results_range]}
        df = pd.DataFrame(data)
        df_indexed = df.set_index('Category')

        return df_indexed

    # Test on main Phishing Detector
    results_spam = create_dataset_statistics(spam_df_combined, "Spam")
    results_easy = create_dataset_statistics(easy_df_combined, "Easy_ham")
    results_hard = create_dataset_statistics(hard_df, "Hard_ham")

    final_df = pd.concat([results_spam, results_easy, results_hard])
    
    end_time = time.perf_counter()
    time_taken = end_time - start_time

    print(f"Program finished. Total execution time: {time_taken:.4f}s")
    print(final_df)