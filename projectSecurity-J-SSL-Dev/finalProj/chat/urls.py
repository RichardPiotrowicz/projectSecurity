from django.urls import path
from . import views

urlpatterns = [
    path('chat/', views.chat, name='chat'),
    # path('login.html', views.login_view, name='login'),
    path('register', views.register_view, name='register'),
]
