from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver

class Account(AbstractUser):
    """
    Custom user model that extends AbstractUser.
    Add any additional fields if needed.
    """
    email = models.CharField(max_length=255, unique=True)
    open_stack_id = models.CharField(blank=True, max_length=50)

    open_stack_token = models.TextField(blank=True)
    token_created_at = models.DateTimeField(blank=True, null=True)
    token_expires_at = models.DateTimeField(blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['password', "username"]

    def __str__(self) -> str:
        return str(self.email)

# model to track failed tasks
class FailedTask(models.Model):
    task_id = models.CharField(max_length=255)
    exc = models.TextField()
    args = models.JSONField()
    kwargs = models.JSONField()
    einfo = models.TextField()

@receiver(post_save, sender=Account)
def create_user_sync(sender, instance, created, **kwargs):
    """
    Signal to sync a newly created user to OpenStack.
    """
    if created:
        from .tasks import sync_user_to_openstack
        sync_user_to_openstack.delay(instance.id)