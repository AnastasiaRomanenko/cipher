from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_protect

from src.authentication.passwords import evaluate_password


@method_decorator(csrf_protect, name="dispatch")
class PasswordStrengthView(View):

    def post(self, request, *args, **kwargs):
        password = request.POST.get("password", "")
        return JsonResponse(evaluate_password(password))
