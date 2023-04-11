import pandas as pd

import joblib
from . import service
from sklearn.metrics import accuracy_score

category = ["benign", "defacement", "phishing", "malware"]


model_list = []
model_names = ['DecModel.pkl', 'RanModel.pkl', 'AdaModel.pkl', 'KNeModel.pkl', 'SGDModel.pkl', 'ExtModel.pkl', 'GauModel.pkl']


def checking(model_list, data):

    X, y = service.preprocessing(data)
        
    print("======================= 전처리 완료 ======================")

    accuracy_test=[]
    


    for i in model_list:
        score = 0.0
        pred = i.predict(X) 
        print("====================================================", i)
        print("====================================================", pred)
        acc = accuracy_score(pred, y)
        accuracy_test.append(acc)
        print('Test Accuracy :\033[32m \033[01m {:.2f}% \033[30m \033[0m'.format(acc*100))
        score += (acc*100)
        

    return score / 7

def categorization(url):

    category_score = []
    
    for i in range(0, 4):
        data = pd.DataFrame({
        "url" : url,
        "type" : category[i]},
        index = [0])

       
        category_score.append(checking(model_list, data))
        

    return category_score


def scoring(url):

    finalScore = []

    result = ""

    for i in range(0, len(model_names)):

        model_list.append(joblib.load(open(model_names[i], 'rb')))

    finalScore = categorization(url)
    
    
    for i in finalScore:
        print("============================== score ===============================", i)

    if(finalScore[0] == max(finalScore)):
        result = "정상"
    else:
        result = "비정상"

    return result




# for i in range(0, len(finalScore)):
#     print(finalScore[i])


# if(finalScore[0] == max(finalScore)):
#     print("이 URL은 정상입니다.")
# else :
#     print("이 URL은 악성웹사이트입니다.")
# elif(sd[1] == sd.max()):
#     print("이 URL은 변조된 웹사이트입니다.")
# elif(sd[2] == sd.max()):
#     print("이 URL은 피싱입니다.")
# else:
#     print("이 URL은 멀웨어 입니다.")


