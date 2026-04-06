# setup.py  — run once: python setup.py
from ids.warehouse import build_warehouse
from ids.ml import train_all

print("=== Step 1: Building warehouse ===")
build_warehouse()

print("\n=== Step 2: Training & pickling all models ===")
train_all()

print("\nSetup complete. Run: streamlit run app.py")