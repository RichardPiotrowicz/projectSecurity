from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
# Create your views here.

def chat(request):
    template = loader.get_template('chatLayout.html')

    return HttpResponse(template.render())