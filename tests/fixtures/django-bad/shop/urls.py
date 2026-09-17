from django.urls import path

from shop import views

urlpatterns = [
    path("invoices/<int:pk>/", views.invoice_detail),
    path("invoices/search/", views.invoice_search),
    path("preview/", views.link_preview),
    path("export/", views.export_invoices),
]
