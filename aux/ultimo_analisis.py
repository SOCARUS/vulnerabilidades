import pandas as pd
from datetime import datetime, timedelta

today = datetime.now()
yesterday = datetime.now() - timedelta(days=1)
today = today.strftime("%Y-%m-%d")
yesterday = yesterday.strftime("%Y-%m-%d")

print("Today:", today)
print("Yesterday:", yesterday)

input_today = pd.read_csv(f"./input/arus/{today}/vulnerabilidades_arus.csv")
input_yesterday = pd.read_csv(f"./input/arus/{yesterday}/vulnerabilidades_arus.csv")

