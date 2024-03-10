import uuid

from django.db import models

from fastuser.models import BaseTable


class MockProject(BaseTable):
    project_id = models.CharField(max_length=100, unique=True, default=lambda: uuid.uuid4().hex)
    project_name = models.CharField(max_length=100)
    project_desc = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "mock项目表"
        db_table = "mock_project_tab"
        unique_together = ["project_id"]


resp_text = """
def execute(req, resp):
    import requests

    url = "http://localhost:8000/api/mock/mock_api/"

    payload = {}
    headers = {
        "accept": "application/json",
        "X-CSRFToken": "fk5wQDlKC6ufRjk7r38pfbqyq7mTtyc5NUUqkFN5lbZf6nyHVSbAUVoqbwaGcQHT",
    }

    response = requests.request("GET", url, headers=headers, data=payload)
    resp.data = response.json()
"""


class MockAPI(BaseTable):
    METHOD_CHOICES = [
        ("GET", "GET"),
        ("POST", "POST"),
        ("PUT", "PUT"),
        ("DELETE", "DELETE"),
        ("PATCH", "PATCH"),
    ]

    project = models.ForeignKey(
        MockProject,
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        blank=True,
        null=True,
        to_field="project_id",
        related_name="mock_apis",
    )
    request_path = models.CharField(max_length=100)
    request_method = models.CharField(max_length=10, choices=METHOD_CHOICES, default="POST")
    request_body = models.JSONField(default=dict, blank=True, null=True)
    response_text = models.TextField(default=resp_text)
    is_active = models.BooleanField(default=True)

    api_name = models.CharField(max_length=100, null=True, blank=True)
    api_desc = models.CharField(max_length=100, null=True, blank=True)
    # uuid hex
    api_id = models.CharField(max_length=32, default=lambda: uuid.uuid4().hex, unique=True)
    enabled = models.BooleanField(default=True)

    # TODO 改成many to many
    # followers: list = models.JSONField(null=True, blank=True, default=[], verbose_name="关注者")

    class Meta:
        verbose_name = "mock接口表"
        db_table = "mock_api_tab"
        unique_together = ["project", "request_path", "request_method"]
        ordering = ["-create_time"]


class MockAPILog(BaseTable):
    api = models.ForeignKey(MockAPI, on_delete=models.DO_NOTHING, db_constraint=False, to_field='api_id',
                            related_name="logs")
    project = models.ForeignKey(
        MockProject,
        on_delete=models.DO_NOTHING,
        db_constraint=False,
        blank=True,
        null=True,
        to_field="project_id",
        related_name="mock_logs",
    )
    request_obj = models.JSONField(default=dict, blank=True)
    response_obj = models.JSONField(default=dict, null=True, blank=True)
    request_id = models.CharField(max_length=100, default=lambda: uuid.uuid4().hex, db_index=True, null=True, blank=True)

    class Meta:
        verbose_name = "mock api log表"
        db_table = "mock_api_log"
        ordering = ["-create_time"]
