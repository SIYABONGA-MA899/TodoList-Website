from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.views import LoginView
from django.views.generic.list import ListView
from django.views.generic.detail import DetailView
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from .models import Task
from django.urls import reverse_lazy
from django.contrib.auth.models import User 
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.mail import send_mail, EmailMessage
from myproj import settings
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from . tokens import generate_token
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator


# Create your views here.

def Home(request):

    return render(request, "myapp/home.html")

def SignUp(request):

    if request.method == 'POST':

        fname = request.POST['fname']
        lname = request.POST['lname']
        username = request.POST['username']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        if User.objects.filter(username = username):

            messages.error(request, "the username you have entered already exists!")
            return redirect('signup')

        if User.objects.filter(email = email):

            messages.error(request, "the email you have entered already exists!")
            return redirect('signup')

        if len(username) < 4:

            messages.error(request, "the username you have entered is too short!")
            return redirect('signup')

        if pass1 != pass2:

            messages.error(request, "corfirmed password does not match password")
            return redirect('signup')

        user = User.objects.create_user(
            
            username = username, 
            email = email, 
            password = pass1)

        user.first_name = fname
        user.last_name = lname
        user.is_active = True
        user.save()

        #welcome message

        subject = "Welcome to Siya's TodoList web app"
        message = "Hello!" +" " + user.first_name + " " + user.last_name + " " + "we sent you a confirmation email"
        from_mail = settings.EMAIL_HOST_USER
        to_list = [user.email,]
        send_mail(subject, message, from_mail, to_list, fail_silently=True)

        # confirm email

        current_site = get_current_site(request)
        email_subject = "confirm your email"
        message2 = render_to_string('email_confirmation.html', {
            'name': user.first_name,
            'surname': user.last_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user),
        })

        email = EmailMessage(
            
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user.email,]
        )

        email.fail_silently = True
        email.send()

        messages.success(request, "you registered successfully!")
        return redirect('signin')

    return render(request, "myapp/signup.html")

def activate(request, uidb64, token):

    try:

        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk = uid)

    except(TypeError, ValueError, OverflowError, User.DoesNotExist):

        user = None
            
        if user is not None and generate_token.check_token(user, token):

            user.is_active = True
            user.save()

            return redirect('login')

        else:

            messages.error(request, "failed to activate, register again")
            return render(request, 'fail_email.html')

def About(request):

    return render(request, "myapp/about.html")

def password_reset_request(request):
	if request.method == "POST":
		password_reset_form = PasswordResetForm(request.POST)
		if password_reset_form.is_valid():
			data = password_reset_form.cleaned_data['email']
			associated_users = User.objects.filter(Q(email=data))
			if associated_users.exists():
				for user in associated_users:
					subject = "Password Reset Requested"
					email_template_name = "myapp/password_message.txt"
					parameters = {
					"email":user.email,
					'domain':'127.0.0.1:8000',
					'site_name': 'Website',
					"uid": urlsafe_base64_encode(force_bytes(user.pk)),
					"user": user,
					'token': default_token_generator.make_token(user),
					'protocol': 'http',
					}

					email = render_to_string(email_template_name, parameters)

					try:
						send_mail(subject, email, '' , [user.email], fail_silently=False)

					except BadHeaderError:

						return HttpResponse('Invalid header found.')

					return redirect ("password_reset_done")

	password_reset_form = PasswordResetForm()
	return render(request, "myapp/password_reset.html", context={"password_reset_form":password_reset_form})

class SignIn(LoginView):

    template_name = "myapp/signin.html"
    fields = "__all__"
    redirect_authenticated_user: True

    def get_success_url(self):
        
        return(reverse_lazy('tasks'))

class FullList(LoginRequiredMixin,ListView):

    model = Task
    template_name = "myapp/list.html"
    context_object_name = "tasks"

    def  get_context_data(self, **kwargs):

        context = super().get_context_data(**kwargs)
        context['tasks'] = context['tasks'].filter(user = self.request.user)

        searcher = self.request.GET.get('search') or ''

        if searcher:

            context['tasks'] = context['tasks'].filter(task__icontains = searcher)

        context['searcher'] = searcher  

        return(context)

class TaskDetail(LoginRequiredMixin,DetailView):

    model = Task
    template_name = "myapp/details.html"
    context_object_name = 'task'


class CreateTask(LoginRequiredMixin,CreateView):

    model = Task
    template_name = "myapp/create.html"
    fields = ["task", "task_description", "complete"]
    success_url = reverse_lazy('tasks')

    def form_valid(self, form):
        form.instance.user = self.request.user
        return(super(CreateTask, self).form_valid(form))

class TaskUpdate(LoginRequiredMixin,UpdateView):

    model = Task
    template_name = "myapp/create.html"
    fields = ["task", "task_description", "complete"]
    success_url = reverse_lazy('tasks')

class TaskDelete(LoginRequiredMixin,DeleteView):

    model = Task
    template_name = "myapp/delete.html"
    context_object_name = 'task'
    success_url = reverse_lazy('tasks')

def SignOut(request):

    logout(request)
    return redirect('home')
