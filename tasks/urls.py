from django.contrib.auth.views import LogoutView
from django.urls import path

from . import views

urlpatterns = [
	path('', views.index, name="list"),
	path('register/', views.register_view, name='register'),
	path('signup/', views.register_view, name='signup'),
	path('login/', views.login_view, name='login'),
	path('login/franceconnect/', views.franceconnect_login_view, name='franceconnect_login'),
	path('login/franceconnect/callback/', views.franceconnect_callback_view, name='franceconnect_callback'),
	path('callback/', views.franceconnect_callback_view, name='franceconnect_callback_public'),
	path('login-callback/', views.franceconnect_callback_view, name='franceconnect_login_callback'),
	path('data-callback/', views.franceconnect_callback_view, name='franceconnect_data_callback'),
	path('logout/', LogoutView.as_view(), name='logout'),
	path('forgot-password/', views.forgot_password_view, name='forgot_password'),
	path('reset-password/<str:token>/', views.reset_password_view, name='reset_password'),
	path('me/', views.me_view, name='me'),
	path('update_task/<str:pk>/', views.updateTask, name="update_task"),
	path('delete_task/<str:pk>/', views.deleteTask, name="delete"),
	path(
		'watchlist/add/<str:provider_slug>/',
		views.addProviderWatchlist,
		name="add_watchlist_provider"
	)
	
]
