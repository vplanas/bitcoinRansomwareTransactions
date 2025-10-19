import pandas as pd

# Ruta al archivo CSV
file_path = '../targets.simple.csv'

# Leer el CSV
df = pd.read_csv(file_path)

# Identificar columnas vacías (solo NaN o cadenas vacías)
empty_columns = df.columns[df.isna().all() | (df.eq('').all())]

# Mostrar las columnas vacías
print("Columnas sin ningún valor:", empty_columns.tolist())
