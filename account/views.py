from rest_framework.decorators import api_view
from .serializers import RegistrationSerializer
from rest_framework.response import Response
from rest_framework import status


@api_view(['POST'])
def registration(request):
    serializer = RegistrationSerializer(data = request.data)
    serializer.is_valid(raise_exception=True)

    serializer.save()

    return Response({"success": "User registered successfully"}, status=status.HTTP_201_CREATED)

