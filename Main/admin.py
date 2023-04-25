from django.contrib import admin

from .models import Question, Answer, Document
# Register your models here.


class QuestionAdmin(admin.ModelAdmin):
    search_fields = ['subject']


admin.site.register(Question, QuestionAdmin)

admin.site.register(Answer)

admin.site.register(Document)