from django.db import models


class Post(models.Model):
    ''' 用户发贴 '''

    uid = models.IntegerField(verbose_name='创建者')
    create_date = models.DateTimeField(
            auto_now_add=True, verbose_name='创建时间',
            )
    update_date = models.DateTimeField(auto_now=True, verbose_name='修改时间')
    title = models.CharField(
            max_length=128, null=False, blank=False, verbose_name='标题',
            )
    content = models.TextField(verbose_name='内容')

    def __str__(self):
        return self.title


class Comment(models.Model):
    ''' 用户回贴 '''

    uid = models.IntegerField(verbose_name='创建者')
    create_date = models.DateTimeField(
            auto_now_add=True, verbose_name='创建时间',
            )
    update_date = models.DateTimeField(auto_now=True, verbose_name='修改时间')
    post_id = models.IntegerField(verbose_name='贴子id')
    content = models.TextField(verbose_name='内容')

    def __str__(self):
        return '{} - {}'.format(self.post_id, self.uid)


class Tag(models.Model):
    ''' 分类标签 '''

    name = models.CharField(
            max_length=128, null=False, blank=False, unique=True,
            verbose_name='名称',
            )

    def __str__(self):
        return self.name


class PostTag(models.Model):
    ''' 贴子--标签 关联表 '''

    post_id = models.IntegerField(verbose_name='贴子id')
    tag_id = models.IntegerField(verbose_name='标签id')

    def __str__(self):
        post = Post.objects.get(pk=self.post_id)
        tag = Tag.objects.get(pk=self.tag_id)
        return '{}-{}'.format(tag.name, post.title)
