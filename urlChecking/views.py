from django.shortcuts import render
from urlChecking.main import *
# Create your views here.


def index(request):

    return render(request, 'index.html')



def checkPro(request):
    result = scoring(request.POST['url'])
    return render(request, 'success.html', {'result' : result})