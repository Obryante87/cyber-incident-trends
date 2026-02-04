import os
import joblib
import pandas as pd
from dotenv import load_dotenv
import psycopg2
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.linear_model import LogisticRegression

load_dotenv()

def pg_conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "cyber"),
        user=os.getenv("POSTGRES_USER", "cyber_user"),
        password=os.getenv("POSTGRES_PASSWORD", "cyber_pass"),
    )

def main():
    conn = pg_conn()
    df = pd.read_sql("SELECT * FROM mart.model_training_set", conn)
    conn.close()

    if df.empty:
        raise RuntimeError("Training set is empty. Load breach data + build marts first.")

    y = df["target_high_impact"].astype(int)
    X = df.drop(columns=["target_high_impact", "event_id"])

    cat_cols = ["industry", "breach_type", "ransomware_flag"]
    num_cols = ["kev_added_30d", "kev_added_90d", "avg_cvss_recent"]

    pre = ColumnTransformer(
        transformers=[
            ("cat", Pipeline([
                ("imp", SimpleImputer(strategy="most_frequent")),
                ("ohe", OneHotEncoder(handle_unknown="ignore"))
            ]), cat_cols),
            ("num", Pipeline([
                ("imp", SimpleImputer(strategy="median")),
            ]), num_cols),
        ]
    )

    model = LogisticRegression(max_iter=500)

    pipe = Pipeline([("pre", pre), ("clf", model)])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    pipe.fit(X_train, y_train)
    proba = pipe.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)

    auc = roc_auc_score(y_test, proba)
    print("AUC:", round(auc, 4))
    print(classification_report(y_test, preds))

    os.makedirs("artifacts", exist_ok=True)
    joblib.dump(pipe, "artifacts/high_impact_model.joblib")
    print("Saved model to artifacts/high_impact_model.joblib")

if __name__ == "__main__":
    main()
