import pandas as pd
import service
import joblib

# ---------Training models--------------------
from sklearn.metrics import plot_confusion_matrix
from sklearn.metrics import plot_roc_curve
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.naive_bayes import GaussianNB


data = pd.read_csv('/Users/choejasil/urlCheck/malicious_phish.csv')
#나중에 DB로 바꿔주기

origin_X, origin_y = service.preprocessing(data)
print("================ original preprocessing done ========================")


# file_path = "/Users/choejasil/Desktop/trainedModel"
# shutil.rmtree(file_path)

# os.mkdir(file_path)

finalModel_list = []
models = [DecisionTreeClassifier, RandomForestClassifier, AdaBoostClassifier,
          KNeighborsClassifier, SGDClassifier, ExtraTreesClassifier, GaussianNB]
model_names = ['DecModel.pkl', 'RanModel.pkl', 'AdaModel.pkl',
               'KNeModel.pkl', 'SGDModel.pkl', 'ExtModel.pkl', 'GauModel.pkl']
for i in models:

    model_ = i()
    fit_model = model_.fit(origin_X, origin_y)
    print(i, "fit 완료")
    joblib.dump(fit_model, open(model_names[models.index(i)], 'wb'))
