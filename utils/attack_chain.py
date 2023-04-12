# class Node:
#     """
#     节点
#     """
#
#     def __init__(self, data: str, v_next: list[str], nextNode=None):
#         # 当前节点的名称
#         if nextNode is None:
#             nextNode = []
#         self.name: str = data
#         # 允许的下一跳
#         self.valid_next_node: list = v_next
#
#         # 已链接的下一跳
#         self.saved_next_node: list = nextNode
#
#
# class Link:
#     def __init__(self, head: Node = None):
#         # 头指针
#         self.head = head
#         self.depth = 0
#
#         if self.head:
#             self.depth += 1
#
#     def insert(self, current_node: Node, node: Node, inserted=False) -> bool:
#         """
#         插入节点
#         :param: current_node: 当前指针指向的节点
#         :param: node: 要插入的节点
#         """
#
#         if self.head == None:
#             # 无值，初始化头指针
#             self.head = node
#             self.depth += 1
#
#             
#             return True
#
#         else:
#             # 已初始化，插入节点
#
#             # 当前指向的节点的下一跳 符合 插入的节点名称
#             if node.name in current_node.valid_next_node:
#
#                 # 判断要插入的节点是否已经在当前节点
#                 has_node = False
#                 for n in current_node.saved_next_node:
#                     if n.name == node.name:
#                         has_node = True
#
#                 if len(current_node.saved_next_node) == 0 and not inserted:
#                     self.depth += 1
#
#                 if not has_node:
#                     # 将节点插入到当前节点的下一跳中
#                     current_node.saved_next_node.append(node)
#
#                     
#                     return True
#             else:
#
#                 # 没有匹配到当前节点，继续匹配下一个节点，直到匹配结束
#                 for c_node in current_node.saved_next_node:
#                     inserted = self.insert(c_node, node, inserted)
#
#     def search(self):
#         pass
#
#     def show(self, node):
#         """
#         显示所有可能的树路径
#         """
#
#         if isinstance(node, list) and len(node) == 0:
#             print()
#             return
#
#         if isinstance(node, Node):
#             print(f"{node.name}", end=" ")
#             self.show(node.saved_next_node)
#         else:
#             [self.show(c_n) for c_n in node]
#
#
# class AttackChains:
#     def __init__(self, root_chains: dict[str, list[str]], sub_chains: dict[str, list[str]]):
#         """
#         root_chains = {
#             "test1": ["test2"],
#             ...
#         }
#         sub_chains = {
#             "user_enum": ["pass_brute", ...],
#             "test2": ["test3"],
#             ...
#         }
#
#         :param root_chains:
#         :param sub_chains:
#         """
#         self.root_node = []
#
#         for r_name, r_list in root_chains.items():
#             # 创建根节点
#             root_node = Link(Node(r_name, r_list))
#             self.root_node.append(root_node)
#
#             # 当前深度允许的下一个节点
#             current_valid_node = r_list
#
#             # 没有就退出
#             if len(current_valid_node) == 0:
#                 break
#
#             # 获取子链所有key
#             sub_keys = list(sub_chains.keys())
#             for i in range(len(sub_keys)):
#                 has_sub_node = False
#
#                 if sub_keys[i] == "":
#                     break
#
#                 cv_node = []
#                 for j in range(0, len(sub_keys) - i - 1):
#                     # 子节点在 当前指针的next_chains中
#                     if sub_keys[j] in current_valid_node and sub_keys[j] != "":
#                         # 添加节点，并将节点前移
#                         root_node.insert(root_node.head, Node(sub_keys[j], sub_chains[sub_keys[j]]))
#                         # sub_keys[j], sub_keys[i] = sub_keys[i], sub_keys[j]
#                         cv_node += sub_chains[sub_keys[j]]
#                         sub_keys[j] = ""
#
#                         has_sub_node = True
#
#                 # 没有下一个节点则退出
#                 if not has_sub_node:
#                     break
#                 current_valid_node = cv_node
#
#     def show_chains(self):
#         for node in self.root_node:
#             self.__show__(node.head, 1, node.depth)
#
#     def __show__(self, node: Node or list, current_depth, depth):
#         if isinstance(node, list) and len(node) == 0:
#             print()
#             return
#
#         if isinstance(node, Node):
#             print(f"{node.name}", end=" ")
#             if current_depth != depth:
#                 print(" --> ", end=" ")
#
#             self.__show__(node.saved_next_node, current_depth + 1, depth)
#         else:
#             [self.__show__(c_n, current_depth, depth) for c_n in node]

# ------------------------------#
from utils.logger import output


class AttackChains:
    """
    预定义攻击链, 通过插件的别名进行匹配
    """

    chain_1 = ["user_enum", "pass_brute", "getSPN", "delegate", "DCSync"]
    chain_2 = ["user_enum", "pass_brute", "getSPN", "constrained_delegation", "DCSync"]

    def __init__(self):
        self.chains = [self.chain_1, self.chain_2]
        self.matched_chains: list[dict] = []

        for chain in self.chains:
            m_chain = {
                "match":False
            }

            for n in chain:
                m_chain[n] = ""

            self.matched_chains.append(m_chain)

    def match(self, node: str) -> None:
        for chain in self.matched_chains:
            if node in chain.keys():
                chain["match"] = True
                chain[node] = True

    def print_chains(self):
        for chain in self.matched_chains:
            if chain["match"]:
                chain.pop("match")

                index = 1
                chain_str = ""
                for k, v in chain.items():
                    if v:
                        chain_str += f"{output.RED}{k}{output.RESET}"
                    else:
                        chain_str += f"{k}"

                    if index != len(chain):
                        chain_str += "-->"
                    index += 1
                output.success(chain_str)


# if __name__ == '__main__':
#     root_chains = {
#         "test1": ["test2.1", "test2.2"],
#         "pp": ["pp2", "pp3"]
#
#     }
#     sub_chains = {
#         "n1": [""],
#         "test3": ["test4"],
#         "n2": ["n2"],
#         "test2.1": ["test3"],
#         "n4": ["n1", "n2"],
#         "test2.2": ["test3"],
#         "n3": [""],
#
#         "pp2": ["pp3", "pp4"],
#         "pp3": ["pp4"],
#         "pp4": "pp5",
#     }
#
#     t = AttackChains(root_chains, sub_chains)
#     t.show_chains()
if __name__ == '__main__':
    test_node = ["user_enum", "delegate", "constrained_delegation"]

    a_chains = AttackChains()
    for n in test_node:
        a_chains.match(n)
    a_chains.print_chains()