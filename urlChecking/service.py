import re
import seaborn as sns
import matplotlib.pyplot as plt

plt.switch_backend("agg")

from colorama import Fore
from urllib.parse import urlparse

from tld import get_tld, is_tld

#---------Training models--------------------
from sklearn.metrics import plot_confusion_matrix
from sklearn.metrics import plot_roc_curve
from sklearn.tree import  DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn import svm

def preprocessing(data):

    #-----Checking for Nan values-----
    
    data.isnull().sum()
    count = data.type.value_counts()
    #print(count)
    x = count.index
    #print(x)

    sns.barplot(x=count.index, y = count)
    plt.xlabel('Types')
    plt.ylabel('Count')
    #plt.show()

    data['url'] = data['url'].replace('www.', '', regex=True)
    #print(data)

    rem = {"Category": {"benign": 0, "defacement": 1, "phishing":2, "malware":3}}
    data['Category'] = data['type']
    data = data.replace(rem)
    


    #----Feature Engineering----

    #길이
    data['url_len'] = data['url'].apply(lambda x: len(str(x)))
    #print(data.head())

    #도메인
    def process_tld(url):
        try:
            res = get_tld(url, as_object = True, fail_silently=False,fix_protocol=True)
            pri_domain= res.parsed_url.netloc
        except :
            pri_domain= None
        return pri_domain

    data['domain'] = data['url'].apply(lambda i: process_tld(i))
    #print(data.head())

    #특수문자
    feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
    for a in feature:
        data[a] = data['url'].apply(lambda i: i.count(a))

    #print(data.head())


    #abnormal_url, 악성 URL 패턴 중 매칭되는 패턴이 있으면 1, 없으면 0
    def abnormal_url(url):
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))

    #print(data.head(10))
    sns.countplot(x='abnormal_url', data=data)
    #plt.show()


    #https 유무
    def httpSecure(url):
        htp = urlparse(url).scheme 
                                
        match = str(htp)
        if match=='https':
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    data['https'] = data['url'].apply(lambda i: httpSecure(i))
    #print(data.head(20))
    sns.countplot(x='https', data=data)
    #plt.show()


    #숫자개수
    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits

    data['digits']= data['url'].apply(lambda i: digit_count(i))
    #print(data.head())


    #문자 개수
    def letter_count(url):
        letters = 0
        for i in url:
            if i.isalpha():
                letters = letters + 1
        return letters

    data['letters']= data['url'].apply(lambda i: letter_count(i))
    #print(data.head())



    #패턴이 있는지 없는지
    def Shortining_Service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        url)
        if match:
            return 1
        else:
            return 0
    data['Shortining_Service'] = data['url'].apply(lambda x: Shortining_Service(x))
    #print(data.head())
    sns.countplot(x='Shortining_Service', data=data)
    #plt.show()


    #IP 접속주소
    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
            '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
        if match:
            return 1
        else:
            return 0
    data['having_ip_address'] = data['url'].apply(lambda i: having_ip_address(i))
    #print(data.head())

    #print(data['having_ip_address'].value_counts())


    plt.figure(figsize=(15, 15))
    sns.heatmap(data.corr(), linewidths=.5)
    #plt.show()


    X = data.drop(['url','type','Category','domain'],axis=1)#,'type_code'
    y = data['Category']

    return X, y


    
