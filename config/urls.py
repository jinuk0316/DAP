from django.contrib import admin
from django.urls import path, include

from Main import views

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),

    # 메인화면
    path('', views.index, name='index'),
    path('<int:question_id>/', views.detail, name='detail'), #
    path('answer/create/<int:question_id>/', views.answer_create, name='answer_create'), # 
    path('question/create/', views.question_create, name='question_create'),
    path('common/', include('common.urls')),
    path('home/', views.home, name='home'),
    path('diagnosis/', views.diagnosis, name='diagnosis'),

    # 질문답변 수정 및 삭제
    path('question/modify/<int:question_id>/', views.question_modify, name='question_modify'),
    path('question/delete/<int:question_id>/', views.question_delete, name='question_delete'),
    path('answer/modify/<int:answer_id>/', views.answer_modify, name='answer_modify'),
    path('answer/delete/<int:answer_id>/', views.answer_delete, name='answer_delete'),

    # 연결 페이지
    path('connect/', views.connect, name='connect'), 
    path('connect_user/', views.connect_user, name='connect_user'),

    # 업로드 페이지
    path('simple_upload/', views.simple_upload, name='simple_upload'),
    path('model_form_upload/', views.model_form_upload, name='model_form_upload'),
    path('model_form/', views.model_form, name='model_form'),

    # 다운로드 페이지
    path('download/', views.download, name='download'),
    
    # 진단 다운로드 페이지
    path('diagnosis/window', views.winsow_diagnosis, name='window_diagnosis'),
    path('diagnosis/linux', views.linux_diagnosis, name='linux_diagnosis'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)