import traceback

import requests
from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404

from shop.models import Invoice


@login_required
def invoice_detail(request, pk):
    invoice = get_object_or_404(Invoice, pk=pk)
    return JsonResponse({"number": invoice.number, "total": invoice.total})


@login_required
def invoice_search(request):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT id FROM shop_invoice WHERE number = '{request.GET['number']}'")
        rows = cursor.fetchall()
    return JsonResponse({"ids": [row[0] for row in rows]})


@login_required
def link_preview(request):
    page = requests.get(request.GET["url"], timeout=5)
    return JsonResponse({"status": page.status_code})


@login_required
def export_invoices(request):
    try:
        data = [invoice.number for invoice in Invoice.objects.filter(user=request.user)]
    except Exception:
        return HttpResponse(traceback.format_exc(), status=500)
    return JsonResponse({"numbers": data})
