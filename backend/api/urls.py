from django.urls import path
from .views import RegisterView, LoginView, HomeView, ProjectView, ProjectCollaboratorsView

from . import views

urlpatterns = [
    path('google-calendar/init/', views.google_calendar_init_view, name='google_calendar_init'),
    path('google-calendar/redirect/', views.google_calendar_redirect_view, name='google_calendar_redirect'),
    path('google-calendar/is-connected/', views.google_calendar_is_connected, name='google_calendar_is_connected'),
    path('google-calendar/events/', views.google_calendar_events, name='google_calendar_events'),

    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("home/", HomeView.as_view(), name='home'),
    path('projetos/', ProjectView.as_view(), name='projetos'),
    path('projetos/<int:project_id>/collaborators/', ProjectCollaboratorsView.as_view(), name='project-collaborators'),
]


