"""Django lab app (single file) implementing the Labyrinth lab contract (see lab/README.md).

Uses Django's real CSRF middleware and signed-cookie sessions, so it tests that the proxy keeps
Host/Origin/cookies intact. No websocket support (that needs Channels).
"""
import json
import os
import sys
import time

from django.conf import settings

settings.configure(
    DEBUG=False,
    SECRET_KEY="lab-only-not-a-secret",
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF=__name__,
    MIDDLEWARE=[
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.middleware.common.CommonMiddleware",
        "django.middleware.csrf.CsrfViewMiddleware",
    ],
    INSTALLED_APPS=["django.contrib.sessions"],
    SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
    CSRF_TRUSTED_ORIGINS=os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",") if os.getenv("CSRF_TRUSTED_ORIGINS") else [],
)

from django.http import HttpResponse, JsonResponse, StreamingHttpResponse, Http404  # noqa: E402
from django.middleware.csrf import get_token  # noqa: E402
from django.shortcuts import redirect  # noqa: E402
from django.urls import path  # noqa: E402
from django.views.decorators.csrf import csrf_exempt  # noqa: E402
from django.views.decorators.http import require_http_methods  # noqa: E402

ITEMS = [{"id": 1, "name": "Widget"}, {"id": 2, "name": "Gadget"}]


def health(request):
    return JsonResponse({"ok": True, "framework": "django"})


@csrf_exempt
def items(request):
    if request.method == "POST":
        return JsonResponse({"id": 3, **json.loads(request.body)}, status=201)
    return JsonResponse(ITEMS, safe=False)


def item(request, iid):
    for it in ITEMS:
        if it["id"] == iid:
            return JsonResponse(it)
    raise Http404("not found")


@require_http_methods(["GET", "POST"])
def login(request):
    if request.method == "POST":
        if request.POST.get("username") == "alice" and request.POST.get("password") == "wonderland":
            request.session["user"] = "alice"
            r = redirect("/dashboard")
            r.set_cookie("theme", "dark")
            return r
        return HttpResponse("invalid credentials", status=401)
    token = get_token(request)
    return HttpResponse(f'<form method="post" action="/login"><input type="hidden" name="csrfmiddlewaretoken" value="{token}">'
                        '<input name="username"><input name="password" type="password"><button>Sign in</button></form>')


def dashboard(request):
    u = request.session.get("user")
    return HttpResponse(f"<h1>Welcome {u}</h1>") if u else redirect("/login")


@csrf_exempt
def checkout(request):
    if request.session.get("user"):
        return JsonResponse({"ok": True, "order": 1001})
    return JsonResponse({"error": "login required"}, status=401)


@csrf_exempt
def upload(request):
    f = request.FILES.get("file")
    return JsonResponse({"size": f.size if f else 0})


def redir(request):
    return redirect("/api/health")


def stream(request):
    def gen():
        for n in range(1, 4):
            yield f"data: tick {n}\n\n"
            time.sleep(0.5)
    return StreamingHttpResponse(gen(), content_type="text/event-stream")


urlpatterns = [
    path("api/health", health), path("api/items", items), path("api/items/<int:iid>", item),
    path("login", login), path("dashboard", dashboard), path("checkout", checkout),
    path("upload", upload), path("redirect", redir), path("stream", stream),
]

from django.core.wsgi import get_wsgi_application  # noqa: E402

application = get_wsgi_application()

if __name__ == "__main__":
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
