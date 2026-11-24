"""Rebuild model.js from the published ClaMP CSV. See README.md."""
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

FEATURES = "NumberOfSections MajorLinkerVersion MinorLinkerVersion SizeOfCode SizeOfInitializedData SizeOfUninitializedData AddressOfEntryPoint SectionAlignment FileAlignment MajorOperatingSystemVersion MajorSubsystemVersion SizeOfImage SizeOfHeaders Subsystem DllCharacteristics".split()
DIGEST = "3f63b88f9d9563394ece5c28bf90fffede46f241dac0d30e0228bb78febaff37"
source = Path(sys.argv[1])
assert hashlib.sha256(source.read_bytes()).hexdigest() == DIGEST, "Unexpected dataset revision"
groups = defaultdict(set)
with source.open(newline="") as stream:
    rows = list(csv.DictReader(stream))
for row in rows:
    vector = tuple(int(row[k]) for k in FEATURES)
    groups[vector].add(int(row["class"]))
samples = [(vector, next(iter(labels))) for vector, labels in groups.items() if len(labels) == 1]
X = np.array([v for v, y in samples])
y = np.array([y for v, y in samples])
train, test = train_test_split(np.arange(len(y)), test_size=0.2, random_state=42, stratify=y)
# Prespecified models and threshold. The linear model powers the demo for exact explanations.
scaler = StandardScaler().fit(np.log1p(X[train]))
Z = scaler.transform(np.log1p(X))
models = {
    "Logistic regression": LogisticRegression(max_iter=2000, random_state=42),
    "Random forest": RandomForestClassifier(n_estimators=160, min_samples_leaf=2, random_state=42),
    "Gradient boosting": GradientBoostingClassifier(n_estimators=100, max_depth=2, random_state=42)
}
metrics = []
for name, clf in models.items():
    clf.fit(Z[train], y[train])
    p = clf.predict_proba(Z[test])[:, 1]
    predicted = (p >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y[test], predicted).ravel().tolist()
    metrics.append(dict(name=name, accuracy=accuracy_score(y[test], predicted),
                        precision=precision_score(y[test], predicted), recall=recall_score(y[test], predicted),
                        f1=f1_score(y[test], predicted), auc=roc_auc_score(y[test], p),
                        fpr=fp/(fp+tn), tn=tn, fp=fp, fn=fn, tp=tp))
linear = models["Logistic regression"]
weights = linear.coef_[0]
probs = linear.predict_proba(Z[test])[:, 1]
examples = []
for label in (0, 1):
    candidates = np.where((y[test] == label) & ((probs >= 0.5) == label))[0]
    pos = candidates[np.argsort(probs[candidates])[len(candidates)//2]]
    examples.append(dict(label=label, features=X[test[pos]].tolist(), expected=float(probs[pos])))
data = dict(version="clamp-lr-v1", features=FEATURES, mean=scaler.mean_.tolist(),
            scale=scaler.scale_.tolist(), weights=weights.tolist(), base=float(linear.intercept_[0]),
            globalImpact=np.mean(np.abs(Z[test]*weights),axis=0).tolist(),
            examples=examples, metrics=metrics, sourceRows=len(rows), train=len(train), test=len(test),
            conflicted=sum(len(v)>1 for v in groups.values()), unique=len(groups), digest=DIGEST,
            trainCounts=np.bincount(y[train]).tolist(), testCounts=np.bincount(y[test]).tolist())
Path(__file__).with_name("model.js").write_text("const MODEL = "+json.dumps(data,allow_nan=False)+";\n",encoding="utf-8")
print(json.dumps(metrics,indent=2))

