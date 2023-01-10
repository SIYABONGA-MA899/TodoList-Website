from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.Home, name = 'home'),
    path('signup/', views.SignUp, name = 'signup'),
    path('signin/', views.SignIn.as_view(), name = 'signin'),
    path('about/', views.About, name = 'about'),
    path('signout/', views.SignOut, name = 'signout'),
    path('tasks/', views.FullList.as_view(), name = 'tasks'),
    path('detail/<int:pk>/', views.TaskDetail.as_view(), name = 'detail'),
    path('create/', views.CreateTask.as_view(), name = 'create'),
    path('update/<int:pk>/', views.TaskUpdate.as_view(), name = 'update'),
    path('delete/<int:pk>/', views.TaskDelete.as_view(), name = 'delete'),
    path('activate/<uidb64>/<token>/', views.activate, name = 'activate'),
    path('password_reset/', views.password_reset_request, name = 'password_reset'),
    path('reset_password_sent/', auth_views.PasswordResetDoneView.as_view(template_name = "myapp/password_reset_sent.html"), name = 'password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name = "myapp/password_reset_confirm.html"), name = 'password_reset_confirm'),
    path('reset_password_complete/', auth_views.PasswordResetCompleteView.as_view(template_name = "myapp/password_reset_complete.html"), name = 'password_reset_complete'),
    
]