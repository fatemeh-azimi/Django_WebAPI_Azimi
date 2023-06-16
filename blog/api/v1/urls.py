from django.urls import path, include
from . import views
from rest_framework.routers import DefaultRouter

app_name = 'api-v1'

#router = DefaultRouter()
#router.register("post", views.PostViewSet, basename="post")
#router.register("category", views.CategoryModelViewSet, basename="category")
#urlpatterns = router.urls


urlpatterns = [
    #path('post/',views.postList,name="post-list"),
    #path('post/<int:id>/',views.postDetail,name="post-detail"),

    #path('post/',views.PostList.as_view(),name="post-list"),
    #path('post/<int:pk>/',views.PostDetail.as_view(), name="post-detail"),

    path('post/',views.PostModelViewSet.as_view({'get':'list', 'post':'create'}), name="post-list"),
    path('post/<int:pk>/',views.PostModelViewSet.as_view({'get':'retrieve', 'put':'update', 'patch':'partial_update', 'delete':'destroy'}), name="post-detail"),
    
    path('category/',views.CategoryModelViewSet.as_view({'get':'list', 'post':'create'}), name="category-list"),
    path('category/<int:pk>/',views.CategoryModelViewSet.as_view({'get':'retrieve', 'put':'update', 'patch':'partial_update', 'delete':'destroy'}), name="category-detail"),
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

