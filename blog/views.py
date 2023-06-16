from django.shortcuts import render
from django.views.generic.base import TemplateView, RedirectView
from django.views.generic import ListView, DetailView, FormView, CreateView, UpdateView, DeleteView
from .models import Post
from .forms import PostForm
from django.contrib.auth.mixins import (LoginRequiredMixin, PermissionRequiredMixin)
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import HttpResponse
from django.shortcuts import get_object_or_404


# LoginRequiredMixin -> مجبور میکنه تا طرف اول لاگین کنه بعد اون کلاس رو فعال میکنه
class PostListView(PermissionRequiredMixin, LoginRequiredMixin, ListView):
    permission_required = 'blog.view_post'
    # queryset = Post.objects.all()
    model = Post
    context_object_name = 'posts'
    paginate_by = 2
    ordering = 'id' #همزمان نمیتواند با تابع پایینی استفاده شود.   

    '''#queryset & model معادل است با دستورات 
    def get_queryset(self):
        posts = Post.objects.filter(statuse=True)
        return posts
    '''

class PostDetailView(LoginRequiredMixin, DetailView):
    model = Post   

'''
class PostCreateView(FormView):
    template_name = 'contact1.html'   
    form_class = PostForm
    success_url = '/blog/post/'

    def form_valid(self, form):
        form.save()
        return super().form_valid(form)
'''

'''
class PostCreateView(FormView):
    template_name = 'contact1.html'
    form_class = PostForm
    success_url = '/blog/post/'
    def form_valid(self, form):
        form.save()
        return super().form_valid(form)
'''

# in class kar nemikone sere savee moshkel dare
class PostCreateView(LoginRequiredMixin, CreateView):
    model = Post
    # fields = ['author', 'title', 'content', 'status', 'category', 'published_date']
    form_class = PostForm
    success_url = '/blog/post/'
    
    def form_valid(self, form):
        form.instance.author = self.request.user
        return super().form_valid(form)

#sare save edit shde moshkel dare
class PostEditView(LoginRequiredMixin, UpdateView):
    model = Post
    form_class = PostForm
    success_url = '/blog/post/'

class PostDeleteView(LoginRequiredMixin, DeleteView):
    model = Post
    success_url = '/blog/post/'


# merge API and page
class PostListApiView(TemplateView):
    template_name = "blog/post_list_api.html"


# ->->->->->->->->->->->->->->->->->->->-> at profile can see my-posts
"""
class UserPostListView(ListView):
    model = Post
    template_name = 'blog/user_posts.html'
    context_object_name='posts'
    paginate_by = 15

    def get_queryset(self):
        user = get_object_or_404(User, username=self.kwargs.get('username'))
        return Post.objects.filter(author=user).order_by('-date_posted')

    def get_context_data(self, **kwargs):
        context = super(UserPostListView, self).get_context_data(**kwargs)
        user = get_object_or_404(User, username=self.kwargs.get('username'))
        context['postuser'] = Post.objects.filter(author=user).order_by('-date_posted')[:1]
        context['posts'] = Post.objects.filter(author=user).order_by('-date_posted')
        return context
"""

# example to function base view and render base view (without API) ->
'''
from django.shortcuts import render,get_object_or_404,redirect
from blog.models import Post,Comment
from django.core.paginator import Paginator,EmptyPage,PageNotAnInteger
from blog.forms import CommentForm
from django.contrib import messages
from django.urls import reverse
from django.http import HttpResponseRedirect
 


def blog_view(request,**kwargs):
    posts = Post.objects.filter(status=1).order_by('-published_date')
    if kwargs.get('cat_name') != None:
        posts = posts.filter(category__name=kwargs['cat_name'])
    if kwargs.get('author_username') != None:
        posts = posts.filter(author__username = kwargs['author_username'])
    if kwargs.get('tag_name') != None:
        posts = posts.filter(tags__name__in=[kwargs['tag_name']])
    posts = Paginator(posts,3)
    try:
        page_number = request.GET.get('page')
        posts = posts.get_page(page_number)
    except PageNotAnInteger:
        posts = posts.get_page(1)
    except EmptyPage:
        posts = posts.get_page(1)
    context = {'posts':posts}
    return render(request,'blog/blog-home.html',context)


def blog_single(request,pid):
    if request.method == 'POST':
        form = CommentForm(request.POST)
        if form.is_valid():
            form.save()
            messages.add_message(request,messages.SUCCESS,'your comment submited successfully')
        else:
            messages.add_message(request,messages.ERROR,'your comment didnt submiter')
    posts = Post.objects.filter(status=1)
    post = get_object_or_404(posts,pk=pid)
    
    if not post.login_require:
        comments = Comment.objects.filter(post=post.id,approved=True)
        form = CommentForm()
        context = {'post':post,'comments':comments,'form':form}

        return render(request,'blog/blog-single.html',context)
    else:
        return HttpResponseRedirect(reverse('accounts:login'))


def blog_search(request):
    #print(request.__dict__)
    posts = Post.objects.filter(status=1)
    if request.method == 'GET':
        #print(request.GET.get('s'))
        # if s := request.GET.get('s'): #use this method only when your using python version 3.8 and above
        if request.GET.get('s'):
            s =  request.GET.get('s')
            posts = posts.filter(content__contains=s)
    
    context = {'posts':posts}
    return render(request,'blog/blog-home.html',context)


def test(request):
    return render(request,'test.html')
'''
# <-
