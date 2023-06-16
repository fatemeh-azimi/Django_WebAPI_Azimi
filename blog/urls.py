from django.urls import path, include
from . import views
from django.views.generic import TemplateView
from django.views.generic.base import RedirectView

app_name = 'blog'

urlpatterns = [
    # path('cvb-index', TemplateView.as_view(template_name="index.html", extra_context={"name":"fatemeh sadat azimi"})),
    # path('cvb-index', views.IndexView.as_view(), name='cvb-test'),
    
    #befor  'rest_framework'
    path('post/', views.PostListView.as_view(), name='post-list'),
    path('post/<int:pk>', views.PostDetailView.as_view(), name='post-detail'),
    path('post/create/', views.PostCreateView.as_view(), name='post-create'),
    path('post/<int:pk>/edit/', views.PostEditView.as_view(), name='post-edit'),
    path('post/<int:pk>/delete/', views.PostDeleteView.as_view(), name='post-delete'),
    
    path('post/api/', views.PostListApiView.as_view(), name='post-list-api'),
    
    path('api/v1/', include('blog.api.v1.urls')),
    path('post/api/', views.PostListApiView.as_view(), name='post-list'),
    
]


# example to function base view and render base view (without API) ->
'''
from django.urls import path
from blog.views import *
from blog.feeds import LatestEntriesFeed
app_name = 'blog'
 
urlpatterns = [
    path('' ,blog_view,name='index'),
    path('<int:pid>' ,blog_single,name='single'),
    path('category/<str:cat_name>' ,blog_view,name='category'),
    path('tag/<str:tag_name>' ,blog_view,name='tag'),
    path('author/<str:author_username>',blog_view,name='author'),
    path('search/',blog_search,name='search'),
    path('rss/feed/', LatestEntriesFeed()),
    #path('test',test,name='test'),
]
'''
# <-

