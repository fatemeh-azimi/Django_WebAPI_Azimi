"""core URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.documentation import include_docs_urls
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.http import HttpResponse


schema_view = get_schema_view(
    openapi.Info(
        title="CustomUser Django API",
        default_version="v1",
        description="A Base authentication app with custom user model",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="f.s.azimi.2001@gmail.com"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny] #میپرسد که چه کسانی میتوانند این صفحه داکیومنت را ببینند؟ 
)



# sitemaps = {
#     'static': StaticViewSitemap,
#     'blog': BlogSitemap
# }


def indexView(request):
    return HttpResponse("<h1>Django Final Test</h1>")


urlpatterns = [
    path('', indexView, name='index'),
    # path('',include('website.urls')),

    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),    
    path('blog/', include('blog.urls')),

    #easy to logIn & logOut
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')), 

    path('api-docs/', include_docs_urls(title='api sample')),

    #documentation -> core.settings.py -> # restframework settings
    path('swagger/output.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),


    # path('summernote/', include('django_summernote.urls')),
    # path('sitemap.xml', sitemap, {'sitemaps': sitemaps}, name='django.contrib.sitemaps.views.sitemap'),
    # path('robots.txt', include('robots.urls')),
    # path('captcha/', include('captcha.urls')),
]


# serving static and media for development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root = settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root = settings.MEDIA_ROOT)


