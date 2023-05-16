import urllib3
from exchangelib import Credentials, Configuration, Account
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter

from utils import output


class ExchangeTool:
    def __init__(self, domain_name, username, password, target_address):

        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
        urllib3.disable_warnings()

        user = f"{username}@{domain_name}"
        credentials = Credentials(user, password)
        config = Configuration(server=target_address, credentials=credentials)
        self.account = Account(user, config=config, autodiscover=False, credentials=credentials)

    def search_email_context(self, context):
        email_result = f"subject{'':^30}sender{'':^20}body\n"

        for item in self.account.inbox.all().order_by('subject'):
            if context == "" and item.body is not None:
                email_result += f"{'':^4}{item.subject}{'':^30}{item.sender.email_address}{'':^20}{item.body}\n"
                continue

            if item.body is not None and context in item.body and item.body.strip() != "":
                email_result += f"{'':^4}{item.subject}{'':^30}{item.sender.email_address}{'':^20}{item.body}\n"

        output.success(email_result)

    def get_all_email_address(self):
        email_address = set()
        for item in self.account.inbox.all().order_by('subject'):
            if item.sender:
                email_address.add(item.sender.email_address)

        output.success("email result:\n" + "\n".join(list(email_address)))
