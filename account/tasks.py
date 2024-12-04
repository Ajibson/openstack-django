from .models import Account, FailedTask
from .utils import create_openstack_user
from asgiref.sync import async_to_sync
from celery import Task, shared_task


class CallbackTask(Task):  # type: ignore # noqa: F821
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # add the failed task to db for later reference
        FailedTask.objects.create(
            task_id=task_id, exc=str(exc), args=args, kwargs=kwargs, einfo=str(einfo)
        )
    # you can also send an alert email

@shared_task(bind=True, base=CallbackTask, max_retries=4)
def sync_user_to_openstack(self, user_id):
    try:
        user_instance = Account.objects.get(id=user_id)
        openstack_user_id = async_to_sync(create_openstack_user)(user_instance)
        print(f"Open stack Id: {openstack_user_id}")
        return "Done"
    except Exception as exc:
        # Retry the task
        raise self.retry(exc=exc, countdown=5)  # retry in 5 seconds