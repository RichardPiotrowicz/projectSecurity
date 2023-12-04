from django.shortcuts import render, redirect
from .forms import MessagesForm
from .models import Messages


def chat(request):
    context = {}

    # create object of form
    form = MessagesForm(request.POST or None, request.FILES or None)

    # check if form data is valid
    if form.is_valid():
        # save the form data to model
        form.save()

    context['form'] = form
    context['data'] = Messages.objects.all()
    return render(request, "chatLayout.html", context)
