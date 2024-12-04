import httpx 
from django.conf import settings 
from .token_mgt import get_openstack_token
from asgiref.sync import sync_to_async
import logging

logger = logging.getLogger("account")

async def create_openstack_user(user_instance): 
    _,token, _, _ = await get_openstack_token(admin_pass='yes') 
    # Assemble the user data for OpenStack 
    user_data = { "user": { "name": user_instance.username, "password": user_instance.password[20:61], "email": user_instance.email, "enabled": True, "options": { "ignore_password_expiry": True } } }
    # OpenStack API endpoint 
    url = f"{settings.OPEN_STACK_AUTH_URL}/v3/users"
    # Asynchronously call OpenStack API to create user 
    async with httpx.AsyncClient(verify=False, timeout=120) as client: 
        user_response = await client.post(url, json=user_data, headers={"X-Auth-Token": token})
        if user_response.status_code != 201: 
            logger.error(f"Failed to create OpenStack user for {user_instance.username}: {user_response.text}")
        openstack_user_id = user_response.json()['user']['id']
        # Save the OpenStack user ID to the Django user instance 
        user_instance.open_stack_id = openstack_user_id 
        await sync_to_async(user_instance.save, thread_sensitive=True)()
        return openstack_user_id