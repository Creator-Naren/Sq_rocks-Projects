#!/usr/bin/env python3
"""Naive Bayes phishing email classifier (lab training dataset).

Builds a CountVectorizer + MultinomialNB pipeline, evaluates on a train/test
split, prints a confusion matrix and accuracy report, and saves artifacts:
    - phish_email_dataset.csv  (50 samples labeled 1=phishing, 0=legit)
    - phish_model.joblib       (trained pipeline)
    - evaluation_report.json   (metrics + test predictions)

Usage:
    python3 phish_detector.py              # train/evaluate and run test cases
    python3 phish_detector.py --gridsearch # optional hyperparameter tuning
"""

from __future__ import annotations

import argparse
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

DATA_FILE = "phish_email_dataset.csv"
MODEL_FILE = "phish_model.joblib"
REPORT_FILE = "evaluation_report.json"

# 50-sample labeled dataset (crafted for training exercise; not production-grade)
EMAILS: list[tuple[str, int]] = [
    ("Urgent: Verify your account now to avoid suspension", 1),
    ("Your PayPal login was blocked; click to restore access", 1),
    ("Action required: Update your banking details immediately", 1),
    ("Win a free iPhone by completing this short survey", 1),
    ("Click here to claim your $500 Amazon gift card", 1),
    ("Your password expires today; reset through this link", 1),
    ("Your account has been compromised; login to secure it", 1),
    ("Limited-time offer: Click to get a 90% discount", 1),
    ("Update your email password now to keep your inbox active", 1),
    ("Urgent wire transfer approval needed for vendor payment", 1),
    ("Click the link below to confirm your delivery address", 1),
    ("Your bank detected unusual activity; verify identity", 1),
    ("Congratulations! You've won; claim your prize now", 1),
    ("You have an undelivered package; pay the fee to release", 1),
    ("Secure your account: We detected a suspicious login", 1),
    ("Get rich quick; click to learn this investment trick", 1),
    ("Reset your 2FA; follow this link to continue", 1),
    ("Your Netflix subscription was canceled; reactivate here", 1),
    ("Urgent: Your tax refund is pending; confirm bank details", 1),
    ("Act now to claim your inheritance", 1),
    ("Team standup at 3pm, agenda attached", 0),
    ("Your invoice for Q2 is ready for review", 0),
    ("Meeting notes from yesterday's client call", 0),
    ("Please review the attached draft proposal", 0),
    ("Weekly engineering report for review", 0),
    ("Your expense report was approved", 0),
    ("Reminder: Submit your timesheet before Friday", 0),
    ("New hire onboarding checklist attached", 0),
    ("Lunch with the sales team on Thursday", 0),
    ("Updated project roadmap attached", 0),
    ("Please RSVP for the all-hands meeting", 0),
    ("Here's the transcript of our recent call", 0),
    ("Performance review feedback attached", 0),
    ("The dev environment is back online", 0),
    ("Shipping delay update for PO-12345", 0),
    ("Customer feedback summary for last week", 0),
    ("Patch notes for release v2.3.4", 0),
    ("Here are the slides for the training session", 0),
    ("Final approval needed on the marketing budget", 0),
    ("Code review comments for PR #47", 0),
    ("Welcome to the new intern cohort", 0),
    ("Conference agenda and speaker list attached", 0),
    ("Reminder: Update your SSH keys this month", 0),
    ("Security patch released for the staging cluster", 0),
    ("Quarterly goals recap and discussion points", 0),
    ("Please sign the NDA attached to this message", 0),
    ("Vacation coverage schedule for next month", 0),
    ("Release freeze starts next week", 0),
    ("Design review notes attached", 0),
    ("Follow-up on the support ticket #8801", 0),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train/evaluate phishing email NB")
    parser.add_argument("--gridsearch", action="store_true",
                        help="run GridSearchCV on CountVectorizer/alpha")
    args = parser.parse_args()

    df = pd.DataFrame(EMAILS, columns=["email", "label"])
    df.to_csv(DATA_FILE, index=False)
    print(f"[written] {DATA_FILE}  ({len(df)} samples, phishing={int((df.label==1).sum())}, legit={int((df.label==0).sum())})")

    X_train, X_test, y_train, y_test = train_test_split(
        df.email, df.label, test_size=0.3, stratify=df.label, random_state=42)

    pipe = Pipeline([
        ("vec", CountVectorizer(lowercase=True, stop_words="english")),
        ("clf", MultinomialNB(alpha=1.0)),
    ])

    if args.gridsearch:
        param_grid = {
            "vec__ngram_range": [(1, 1), (1, 2), (2, 2)],
            "vec__max_features": [None, 50, 100],
            "clf__alpha": [0.1, 0.5, 1.0, 2.0],
        }
        grid = GridSearchCV(pipe, param_grid, cv=5, scoring="accuracy", n_jobs=-1)
        grid.fit(df.email, df.label)
        print("\n=== GridSearch best params ===")
        print(json.dumps(grid.best_params_, indent=2))
        pipe = grid.best_estimator_

    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    joblib.dump(pipe, MODEL_FILE)
    print(f"[written] {MODEL_FILE}")

    cm = confusion_matrix(y_test, y_pred)
    cr = classification_report(y_test, y_pred, target_names=["LEGIT", "PHISHING"])

    print("\n=== Confusion matrix (rows true, cols pred) [LEGIT, PHISHING] ===")
    print(cm)
    print("\n=== Classification report ===")
    print(cr)

    test_cases = [
        "Please verify your PayPal login immediately",
        "Meeting notes from yesterday's client call",
        "Update your bank details to avoid account closure",
        "Reminder: Submit your timesheet before Friday",
        "You have an undelivered package; pay the fee",
        "Weekly engineering report attached",
    ]
    preds = pipe.predict(test_cases)

    print("\n=== Test set predictions ===")
    for text, p in zip(test_cases, preds):
        print(f"{'PHISHING' if p else 'LEGIT'}: {text}")

    report = {
        "dataset": DATA_FILE,
        "test_size": 0.3,
        "accuracy": accuracy_score(y_test, y_pred),
        "confusion_matrix": cm.tolist(),
        "classification_report": cr,
        "test_predictions": [
            {"text": t, "label": int(p), "pred": "PHISHING" if p else "LEGIT"}
            for t, p in zip(test_cases, preds)
        ],
    }
    with open(REPORT_FILE, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\n[written] {REPORT_FILE}")


if __name__ == "__main__":
    main()
