import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Q
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from fastrunner import models, serializers

from rest_framework.response import Response
from fastrunner.utils import response
from fastrunner.utils import prepare
from fastrunner.utils.decorator import request_log


class TestCaseView(GenericViewSet):
    queryset = models.Case.objects
    serializer_class = serializers.CaseSerializer
    tag_options = {
        "冒烟用例": 1,
        "集成用例": 2,
        "监控脚本": 3
    }

    @staticmethod
    def case_step_search(search):
        """
        搜索case_step的url或者name
        返回对应的case_id
        """
        case_id = models.CaseStep.objects.filter(Q(name__contains=search) | Q(url__contains=search)).values('case_id')

        case_id = set([item['case_id'] for _, item in enumerate(case_id)])
        return case_id

    @method_decorator(request_log(level='INFO'))
    def get(self, request):
        """
        查询指定CASE列表，不包含CASE STEP
        {
            "project": int,
            "node": int
        }
        """
        node = request.query_params["node"]
        project = request.query_params["project"]
        search = request.query_params["search"]
        case_name_or_url = request.query_params["caseNameOrUrl"]
        # update_time 降序排列
        queryset = self.get_queryset().filter(project__id=project).order_by('-update_time')

        if search != '':
            queryset = queryset.filter(name__contains=search)

        if node != '':
            queryset = queryset.filter(relation=node)

        if case_name_or_url != '':
            case_id = self.case_step_search(case_name_or_url)
            queryset = queryset.filter(pk__in=case_id)

        pagination_query = self.paginate_queryset(queryset)
        serializer = self.get_serializer(pagination_query, many=True)

        return self.get_paginated_response(serializer.data)

    @method_decorator(request_log(level='INFO'))
    def copy(self, request, **kwargs):
        """
        pk int: test id
        {
            name: test name
            relation: int
            project: int
        }
        """
        pk = kwargs['pk']
        name = request.data['name']
        if '|' in name:
            resp = self.split(pk, name)
        else:
            case = models.Case.objects.get(id=pk)
            case.id = None
            case.name = name
            case.save()

            case_step = models.CaseStep.objects.filter(case__id=pk)

            for step in case_step:
                step.id = None
                step.case = case
                step.save()
            resp = response.CASE_ADD_SUCCESS

        return Response(resp)

    def split(self, pk, name):
        split_case_name = name.split('|')[0]
        split_condition = name.split('|')[1]

        # 更新原本的case长度
        case = models.Case.objects.get(id=pk)
        case_step = models.CaseStep.objects.filter(case__id=pk, name__icontains=split_condition)
        # case_step = case_step.filter(Q(method='config') | Q(name__icontains=split_condition))
        case_step_length = len(case_step)
        case.length -= case_step_length
        case.save()

        new_case = models.Case.objects.filter(name=split_case_name).last()
        if new_case:
            new_case.length += case_step_length
            new_case.save()
            case_step.update(case=new_case)
        else:
            # 创建一条新的case
            case.id = None
            case.name = split_case_name
            case.length = case_step_length
            case.save()

            # 把原来的case_step中的case_id改成新的case_id
            case_step.update(case=case)
        # case_step.filter(name=).update_or_create(defaults={'case_id': case.id})
        return response.CASE_SPILT_SUCCESS

    @method_decorator(request_log(level='INFO'))
    def patch(self, request, **kwargs):
        """
        更新测试用例集
        {
            name: str
            id: int
            body: []
            project: int
        }
        """

        pk = kwargs['pk']
        project = request.data.pop("project")
        body = request.data.pop('body')
        relation = request.data.pop("relation")

        if models.Case.objects.exclude(id=pk). \
                filter(name=request.data['name'],
                       project__id=project,
                       relation=relation).first():
            return Response(response.CASE_EXISTS)

        case = models.Case.objects.get(id=pk)

        prepare.update_casestep(body, case)

        request.data['tag'] = self.tag_options[request.data['tag']]
        models.Case.objects.filter(id=pk).update(update_time=datetime.datetime.now(), **request.data)

        return Response(response.CASE_UPDATE_SUCCESS)

    @method_decorator(request_log(level='INFO'))
    def post(self, request):
        """
        新增测试用例集
        {
            name: str
            project: int,
            relation: int,
            tag:str
            body: [{
                id: int,
                project: int,
                name: str,
                method: str,
                url: str
            }]
        }
        """

        try:
            pk = request.data['project']
            request.data['project'] = models.Project.objects.get(id=pk)

        except KeyError:
            return Response(response.KEY_MISS)

        except ObjectDoesNotExist:
            return Response(response.PROJECT_NOT_EXISTS)

        body = request.data.pop('body')

        request.data['tag'] = self.tag_options[request.data['tag']]
        models.Case.objects.create(**request.data)

        case = models.Case.objects.filter(**request.data).first()

        prepare.generate_casestep(body, case)

        return Response(response.CASE_ADD_SUCCESS)

    @method_decorator(request_log(level='INFO'))
    def delete(self, request, **kwargs):
        """
        pk: test id delete single
        [{id:int}] delete batch
        """
        pk = kwargs.get('pk')

        try:
            if pk:
                prepare.case_end(pk)
            else:
                for content in request.data:
                    prepare.case_end(content['id'])

        except ObjectDoesNotExist:
            return Response(response.SYSTEM_ERROR)

        return Response(response.CASE_DELETE_SUCCESS)


class CaseStepView(APIView):
    """
    测试用例step操作视图
    """

    @method_decorator(request_log(level='INFO'))
    def get(self, request, **kwargs):
        """
        返回用例集信息
        """
        pk = kwargs['pk']

        queryset = models.CaseStep.objects.filter(case__id=pk).order_by('step')

        serializer = serializers.CaseStepSerializer(instance=queryset, many=True)

        resp = {
            "case": serializers.CaseSerializer(instance=models.Case.objects.get(id=pk), many=False).data,
            "step": serializer.data
        }
        return Response(resp)
