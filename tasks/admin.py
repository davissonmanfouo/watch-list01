from django.contrib import admin

from .models import PasswordResetToken, Task, UserProfile


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "user", "complete", "provider_service_id", "created")
    list_filter = ("complete", "provider_service_id")
    search_fields = ("title", "user__username", "user__email")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "email_verified", "created")
    list_filter = ("email_verified",)
    search_fields = ("user__username", "user__email")


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "expires_at", "used_at", "created")
    list_filter = ("used_at",)
    search_fields = ("user__username", "user__email")
