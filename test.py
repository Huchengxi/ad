# -*- coding: utf-8 -*-
# from __future__ import unicode_literals
from __future__ import absolute_import

from django import forms
# import ldap
import traceback
from .models import SystemConfig, UserInfo
import ldap

def _get_secret_key(sys_config=None):
    try:
        if sys_config is None:
            sc = SystemConfig.objects.first()
        else:
            sc = sys_config
        secret_key = sc.secret_key
        return secret_key
    except:
        return None


def _get_domain(sys_config=None):
    try:
        if sys_config is None:
            sc = SystemConfig.objects.first()
        else:
            sc = sys_config
        domain = sc.domain_name
        return domain
    except:
        return None

def _get_domain_group(sys_config=None):
    try:
        if sys_config is None:
            sc = SystemConfig.objects.first()
        else:
            sc = sys_config
        domain_group = sc.domain_group
        return domain_group
    except:
        return None


def _get_base_dn(sys_config=None):
    try:
        if sys_config is None:
            sc = SystemConfig.objects.first()
        else:
            sc = sys_config
        base_dn = sc.base_dn
        return base_dn
    except:
        return None


def _get_user_base_dn(sys_config=None):
    base_dn = _get_base_dn(sys_config)
    if base_dn is None:
        return base_dn
    sub_dn_list = base_dn.split(",")
    sub_dn_list = [sub_dn.replace("DC=", "") for sub_dn in sub_dn_list]
    user_dn = ".".join(sub_dn_list)
    return user_dn


def secret_key_match(request):
    secret_key = _get_secret_key()
    if secret_key is None:
        return False

    if request.META.get('HTTP_SECRET_KEY') == secret_key:
        return True
    return False


def get_group_recursion(conn, group_name, group_list=None): # ???????
    if group_list is None:
        group_list = [group_name]
    else:
        group_list.append(group_name)

    base = "DC=pharmatechs,DC=com"
    criteria = "(&(objectClass=group)(memberOf:=%s))"% group_name
    result = conn.search_s(base, ldap.SCOPE_SUBTREE, criteria, [])
    for dn, entry in result:
        if isinstance(entry, dict):
            get_group_recursion(conn, dn, group_list)
    return group_list


def auth_user(username, password):
    for sys_config in SystemConfig.objects.all():
        if auth_user_in_dn(sys_config, username, password) is True:
            return True
    return False


def auth_user_in_dn(sys_config, username, password):
    domain_name = _get_domain(sys_config)
    base_dn = _get_base_dn(sys_config)
    domain_group = _get_domain_group(sys_config)
    user_base_dn = _get_user_base_dn(sys_config)
    if (domain_name is None) or (base_dn is None) or (domain_group is None):
        return False

    try:
        bind_username = "@".join([username, user_base_dn])
        conn = ldap.initialize(domain_name)
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.simple_bind_s(bind_username, password)
        group_list = get_group_recursion(conn, domain_group)
        criteria = "(&(objectClass=user)(sAMAccountName=%s))"% username
        attributes = ['displayName', 'mail', 'mobile']
        result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, criteria, attributes)
        for dn, entry in result:
            if isinstance(entry, dict):
                dn_criteria = "(member=%s)"% dn
                dn_attributes = []
                group_result = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, dn_criteria, dn_attributes)
                for group, _ in group_result:
                    if group in group_list:
                        if UserInfo.objects.filter(username=username).count() == 0:
                            UserInfo.objects.create(
                                username=username,
                                real_name=entry["displayName"][0],
                                mobile_phone=entry.get("mobile", [""])[0],
                                email=entry["mail"][0],
                            )
                        return True
        return False
    except:
        print traceback.format_exc()
    finally:
        conn.unbind()

def search_user_local(username):
    user_info_set = UserInfo.objects.filter(username=username)
    if user_info_set.count() > 0:
        user_info = user_info_set[0]
        return {
            "username": username,
            "real_name": user_info.real_name,
            "mobile_phone": user_info.mobile_phone,
            "email": user_info.email,
        }
    return None
