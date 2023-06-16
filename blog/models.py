from django.db import models
from django.urls import reverse
from accounts.models import Profile, User
from taggit.managers import TaggableManager

# getting user model object
# from django.contrib.auth import get_user_model
# User = get_user_model()


class Post(models.Model):
    """
    dis is a class to define posts for blog app.
    """
    image = models.ImageField(null=True, blank=True, upload_to='blog/',default='blog/default.jpg')
    """
    p 59 begiining  for up
    """
    author = models.ForeignKey('accounts.Profile', on_delete=models.CASCADE)  # ,on_delete=models.SET_NULL,null=True    
    '''
    author = models.ForeignKey(User, on_delete=models.CASCADE)      
    #author = models.ForeignKey('accounts.Profile', on_delete=models.CASCADE)      
    #author = models.ForeignKey(Profile, on_delete=models.CASCADE)   
    '''   
    title = models.CharField(max_length=255)
    content = models.TextField()
    # tags = TaggableManager()
    category = models.ForeignKey('Category', on_delete=models.SET_NULL, null=True)
    # category = models.ManyToManyField('Category')
    counted_views = models.IntegerField(default=0)
    status = models.BooleanField(default=False)
    # login_require = models.BooleanField(default=False)
    published_date = models.DateTimeField()
    # published_date = models.DateTimeField(null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_date']
    
    def __str__(self) -> str:
        return self.title
    
    def get_snippet(self):
        return self.content[0:100] + '...'
    
    def get_absolute_api_url(self):
        return reverse('blog:api-v1:post-detail', kwargs={'pk': self.pk})
        # return reverse('blog:single',kwargs={'pid':self.id})


class Category(models.Model):
    """
    this is a class to define categories for blog table
    """
    name = models.CharField(max_length=255)

    def __str__(self) -> str:
        return self.name


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE)
    name = models.ForeignKey('accounts.Profile', on_delete=models.CASCADE)      
    # name = models.CharField(max_length=255)
    email = models.ForeignKey('accounts.User', on_delete=models.CASCADE)      
    # email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    approved = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_date']

    def __str__(self):
        return self.subject
    
    