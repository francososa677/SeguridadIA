import pandas as pd
df = pd.read_csv("datasets/test_balanced_benchmark.csv")
print(df["lenguaje"].value_counts())