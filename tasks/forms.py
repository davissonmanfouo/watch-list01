from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import Task


User = get_user_model()


class TaskForm(forms.ModelForm):
    title = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "placeholder": "Ajouter un film ou une serie",
                "autocomplete": "off",
            }
        ),
        max_length=200,
    )

    class Meta:
        model = Task
        fields = ["title", "complete"]


class RegisterForm(forms.Form):
    username = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(max_length=254, required=True)
    password = forms.CharField(
        required=True,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )
    password_confirm = forms.CharField(
        required=True,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )
    accept_tos = forms.BooleanField(required=True)

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("Cet email est déjà utilisé.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")
        username = cleaned_data.get("username")
        email = cleaned_data.get("email")

        if password and password_confirm and password != password_confirm:
            self.add_error("password_confirm", "La confirmation ne correspond pas.")

        if password:
            candidate_user = User(username=username or "", email=email or "")
            try:
                validate_password(password, user=candidate_user)
            except ValidationError as exc:
                self.add_error("password", exc)

        return cleaned_data


class LoginForm(forms.Form):
    email = forms.EmailField(max_length=254, required=True)
    password = forms.CharField(
        required=True,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )
    remember_me = forms.BooleanField(required=False)


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(max_length=254, required=True)


class ResetPasswordForm(forms.Form):
    password = forms.CharField(
        required=True,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )
    password_confirm = forms.CharField(
        required=True,
        min_length=8,
        max_length=128,
        widget=forms.PasswordInput(render_value=False),
    )

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirm = cleaned_data.get("password_confirm")

        if password and password_confirm and password != password_confirm:
            self.add_error("password_confirm", "La confirmation ne correspond pas.")

        if password:
            try:
                validate_password(password, user=self.user)
            except ValidationError as exc:
                self.add_error("password", exc)

        return cleaned_data
