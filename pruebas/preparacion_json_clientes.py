import pandas as pd


df = pd.read_csv(
    "./agentes/agentes_actualizado.csv",
    dtype={"ID": "string"},
)

# El campo Group viene como texto que representa un array, por ejemplo:
# '["STF-SERVERS-WINDOWS"]'
# Queremos quedarnos solo con el primer valor del array.

df["ID"] = df["ID"].astype("string")
print(df["ID"].head())
df["Group_first"] = (
    df["Group"]
    .fillna("[]")
    .astype(str)
    .str.strip("[]")
    .str.replace('"', "", regex=False)
    .str.split(",")
    .str[0]
    .str.strip()
)

# Filtro simple por el primer valor del array
stf = df[df["Group_first"] == "STF-SERVERS-WINDOWS"].copy()

# Filtro con dos condiciones
stf = df[
    (df["Group_first"] == "STF-SERVERS-WINDOWS")
    | (df["Group_first"] == "STF-SERVER-LINUX")
].copy()


prebel = df[
    (df["Group_first"] == "Prebel-Linux")
    | (df["Group_first"] == "Prebel-Windows")
].copy()


personalsoft = df[
    (df["Group_first"] == "PersonalSoft-Linux")
    | (df["Group_first"] == "PersonalSoft-Windows")
].copy()

print("stf")
print(stf["ID"].to_list())

print("personalsoft")
print(personalsoft["ID"].to_list())

print("prebel")
print(prebel["ID"].to_list())

