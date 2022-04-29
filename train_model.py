# importing libraries
import xgboost as xgb
import pandas as pd
import os
from sklearn.model_selection import train_test_split

### DATA PROCESSING ###

dfs = []
cwd = os.getcwd()
data_dir = os.path.join(cwd, 'cicids2017/TrafficLabelling')

# opening the directory, and reading all the files. it is expected that they
# all will be csv only
for filename in os.listdir(data_dir):
    filepath = os.path.join(data_dir, filename)
    df = pd.read_csv(filepath, encoding='cp1252')
    dfs.append(df)

# storing in single DataFrame
df = pd.concat(dfs)

# some columns have whitespaces around them, so we are renaming them without
# all the whitespaces
renamed_names = {}
for column_name in df.columns:
    renamed_names[column_name] = column_name.strip()
df.rename(renamed_names, axis=1, inplace=True)

# selecting only the columns that we need, drop the rows with missing
# datapoints
dft = df[[
    'PSH Flag Count',
    'Flow Duration',
    'SYN Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Total Length of Fwd Packets',
    'Active Mean',
    'Active Min',
    'Init_Win_bytes_forward',
    'Subflow Fwd Bytes',
    'Flow IAT Min',
    'Label',
]].dropna().sample(frac=1)

# splitting into model input and output
X = dft[[
    'PSH Flag Count',
    'Flow Duration',
    'SYN Flag Count',
    'ACK Flag Count',
    'Average Packet Size',
    'Total Length of Fwd Packets',
    'Active Mean',
    'Active Min',
    'Init_Win_bytes_forward',
    'Subflow Fwd Bytes',
    'Flow IAT Min',
]]
y = dft[['Label']]

# we will only do binary classification, so all 'BENIGN' flows are labelled as
# 0, and all other non-benign traffic is labelled as 1, denoting that it is
# some form of attack.
y = dft[['Label']]
y['Label'] = y['Label'].apply(lambda label: 0 if label == 'BENIGN' else 1)

# splitting into test and train datasets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.33, random_state=42)

# converting to the format accepted by XGBoost model
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)

### MODEL TRAINING ###

# training a model using GPU
bst = xgb.train({'tree_method': 'gpu_hist'}, dtrain, 10,
                [(dtest, 'eval'), (dtrain, 'train')])

# saving in format XGBoost can reload the model without retraining
bst.save_model('model_output')
# saving in format which can be used by our custom parser to generate
# match-and-action rules for p4 switch
bst.save_model('model_output.json')
