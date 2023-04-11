from django.urls import path
from urlChecking.views import *

app_name = "urlChecking"

urlpatterns = [
    path('',index, name='index'),
    path('checkPro/', checkPro, name='checkPro')
]