"""
Random Forest baseline for the RPL selective-forwarding per-node dataset.

CAVEAT (read before citing results): 'dropped' and 'drop_rate' are computed
directly from a counter that increments ONLY inside the malicious code path
(IS_MALICIOUS). This makes them near-perfect predictors by construction —
this baseline validates the data pipeline and gives an upper-bound sanity
check, not a realistic externally-observable IDS. A follow-up model should
use features a real detector could actually see from outside the attacker's
own memory (e.g. neighbor-reported forwarding ratios, RSSI, RPL parent
churn) rather than the node's own internal drop counter.
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, average_precision_score

# ---- Load ----
df = pd.read_csv("data/per_node_dataset.csv")
df = df.dropna(subset=["malicious"])  # drop any rows where STATS read failed (should be none)
print(f"Loaded {len(df)} node-scenario rows")
print(df["malicious"].value_counts(), "\n")

# ---- Features / label ----
# NOTE: drop_pct is excluded — it's an experiment-design parameter (the attacker's
# configured intensity), not something a detector observes. total/dropped/drop_rate
# ARE included here for this baseline despite the leakage caveat above; see docstring.
feature_cols = ["total", "dropped", "drop_rate"]
X = df[feature_cols]
y = df["malicious"].astype(int)

# ---- Split (stratified to preserve the ~91/9 class balance in both sets) ----
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, stratify=y, random_state=42
)
print(f"Train: {len(X_train)} rows ({y_train.mean():.1%} malicious)")
print(f"Test:  {len(X_test)} rows ({y_test.mean():.1%} malicious)\n")

# ---- Train ----
clf = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    class_weight="balanced",   # compensates for the 91/9 imbalance
    random_state=42,
    n_jobs=-1,
)
clf.fit(X_train, y_train)

# ---- Evaluate ----
y_pred = clf.predict(X_test)
y_proba = clf.predict_proba(X_test)[:, 1]

print("=== Classification report ===")
print(classification_report(y_test, y_pred, target_names=["normal", "malicious"], digits=4))

print("=== Confusion matrix ===")
print("        pred_normal  pred_malicious")
cm = confusion_matrix(y_test, y_pred)
print(f"normal       {cm[0][0]:6d}          {cm[0][1]:6d}")
print(f"malicious    {cm[1][0]:6d}          {cm[1][1]:6d}\n")

print(f"ROC-AUC:  {roc_auc_score(y_test, y_proba):.4f}")
print(f"AUC-PR:   {average_precision_score(y_test, y_proba):.4f}\n")

print("=== Feature importance ===")
for name, imp in sorted(zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1]):
    print(f"  {name:12s} {imp:.4f}")
