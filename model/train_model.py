#!/usr/bin/env python3
"""
train_model.py  --  Stages 7-9 of the project plan:
"Feature Selection", "Model Training", and "Model Evaluation"

WHAT THIS STAGE IS FOR
-------------------------
Stage 6 gave us a table (dataset/arp_dataset.csv): one row per ARP packet,
with a handful of numeric features, and a label saying whether it was
normal (0) or attack (1). This stage teaches a machine learning model to
predict that label FROM the features alone -- so that later (Stage 10-13)
it can look at a brand new, never-seen-before packet and guess correctly
whether it's part of an attack, without us having generated it ourselves.

THE FEATURES WE TRAIN ON
----------------------------
Same six numbers build_dataset.py computed for every packet:

    is_reply, is_gratuitous, claimed_ip_mac_count,
    mac_changed_from_last, pkt_rate_last_5s, time_since_last_pkt

We deliberately leave OUT src_ip, src_mac, dst_ip, time and source_file --
those identify a SPECIFIC packet, but we want the model to learn the
general PATTERN of spoofing (one IP, multiple MACs; high repeat rate),
not memorise "10.0.0.2 is always the attacker", which would be useless
against a differently-numbered network.

WHY TWO MODELS
-------------------
We train two different kinds of classifier and keep whichever scores
better on held-out data:

  Random Forest   : a bundle of decision trees voting together. Easy to
                    interpret (we can ask it which features mattered most),
                    and a solid, fast baseline.

  XGBoost         : a more powerful "gradient boosted trees" model, often
                    the strongest option for exactly this kind of tabular,
                    numeric-feature data. Usually edges out Random Forest
                    a little, at the cost of being a bit more of a black box.

TRAIN/TEST SPLIT -- WHY WE HOLD DATA BACK
-----------------------------------------------
We don't train on 100% of the data. We set aside 20% (the "test set") that
the model never sees during training, then check its predictions against
that held-back 20% afterwards. This is the only honest way to measure
whether the model actually LEARNED the pattern, versus just memorised the
exact rows it was shown. "stratify=y" below means that split keeps the
same normal/attack ratio in both halves, so a lucky/unlucky split doesn't
accidentally give the test set only one class.

THE METRICS WE PRINT, IN PLAIN TERMS
-----------------------------------------
  Accuracy   : % of all predictions that were correct. Can be misleading
               if one class is much rarer than the other (e.g. 95% normal,
               5% attack -- a model that always guesses "normal" scores
               95% accuracy while catching zero attacks).

  Precision  : of everything the model FLAGGED as an attack, what fraction
               really was one? Low precision = too many false alarms.

  Recall     : of everything that TRULY was an attack, what fraction did
               the model catch? Low recall = attacks slipping through
               undetected -- usually the worse failure mode for a security
               tool.

  F1 score   : one number balancing precision and recall together.

  Confusion matrix : a small table of (actually normal / actually attack)
               vs (predicted normal / predicted attack), so you can see
               exactly what kind of mistakes the model makes, not just
               a single summary number.

HOW TO RUN IT
----------------
No Mininet/root needed -- it just reads the CSV Stage 6 produced:

    cd arp-spoofing-detector/model
    python3 train_model.py

OUTPUT
--------
    model/arp_model.pkl   -- the trained model, ready for Stage 10-13's
                              real-time detector to load and use.
"""

import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                              f1_score)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

DATASET_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dataset", "arp_dataset.csv")
MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp_model.pkl")

FEATURE_COLUMNS = [
    "is_reply",
    "is_gratuitous",
    "claimed_ip_mac_count",
    "mac_changed_from_last",
    "pkt_rate_last_5s",
    "time_since_last_pkt",
]

MIN_ROWS_PER_CLASS = 10   # below this, a train/test split isn't meaningful


def load_dataset():
    if not os.path.exists(DATASET_CSV):
        print(f"ERROR: {DATASET_CSV} not found. Run Stage 6's "
              f"build_dataset.py first.")
        return None

    df = pd.read_csv(DATASET_CSV)
    counts = df["label"].value_counts()
    print(f"*** Loaded {len(df)} rows: "
          f"{counts.get(0, 0)} normal, {counts.get(1, 0)} attack")

    if len(counts) < 2:
        print("ERROR: the dataset only contains ONE label (all normal, or "
              "all attack). Run both generate_normal_traffic.py AND "
              "simulate_attack.py, then re-run build_dataset.py.")
        return None

    if counts.min() < MIN_ROWS_PER_CLASS:
        print(f"WARNING: the smaller class only has {counts.min()} rows. "
              f"That's too few to train or evaluate reliably -- treat any "
              f"results below as a smoke test, not a real result. Re-run "
              f"the capture stages for longer (bigger DURATION_SECONDS) to "
              f"get more data, then re-run build_dataset.py.")

    return df


def train_and_compare(df):
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y,
    )
    print(f"*** Split into {len(X_train)} training rows, {len(X_test)} test rows")

    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200, random_state=42, class_weight="balanced"
        ),
        "XGBoost": XGBClassifier(
            n_estimators=200, random_state=42, eval_metric="logloss"
        ),
    }

    best_name, best_model, best_f1 = None, None, -1.0
    for name, model in candidates.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        print(f"\n=== {name} ===")
        print(classification_report(y_test, y_pred, target_names=["normal", "attack"], zero_division=0))
        print("Confusion matrix (rows=actual, cols=predicted; order: normal, attack):")
        print(confusion_matrix(y_test, y_pred, labels=[0, 1]))

        score = f1_score(y_test, y_pred, zero_division=0)
        if score > best_f1:
            best_name, best_model, best_f1 = name, model, score

    print(f"\n*** Best model: {best_name} (F1 = {best_f1:.3f})")
    return best_name, best_model


def print_feature_importance(name, model):
    if not hasattr(model, "feature_importances_"):
        return
    print(f"\n*** What {name} relied on most (higher = more important):")
    pairs = sorted(zip(FEATURE_COLUMNS, model.feature_importances_),
                    key=lambda p: p[1], reverse=True)
    for feature, importance in pairs:
        print(f"    {feature:<25s} {importance:.3f}")


def run():
    df = load_dataset()
    if df is None:
        return

    best_name, best_model = train_and_compare(df)
    print_feature_importance(best_name, best_model)

    joblib.dump({"model": best_model, "features": FEATURE_COLUMNS, "model_name": best_name}, MODEL_PATH)
    print(f"\n*** Saved trained model to {MODEL_PATH}")


if __name__ == "__main__":
    run()