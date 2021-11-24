from typing import List
import socket
import ipaddress
import itertools
import time

from volatility3.framework import renderers, interfaces, objects, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist, lsmod
from volatility3.framework.objects import utility


class Netcon(interfaces.plugins.PluginInterface):
    """Target system network connections."""

    _required_framework_version = (1, 0, 0)

    _version = (1, 0, 0)

    linux_tcp_states = {
        1: "ESTABLISHED",
        2: "SYN_SENT",
        3: "SYN_RECV",
        4: "FIN_WAIT1",
        5: "FIN_WAIT2",
        6: "TIME_WAIT",
        7: "CLOSE",
        8: "CLOSE_WAIT",
        9: "LAST_ACK",
        10: "LISTEN",
        11: "CLOSING",

        12: "MAX_STATES"
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Memory layer for the kernel',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolTableRequirement(name="nt_symbols",
                                                    description="Windows kernel symbols"),
                requirements.SymbolTableRequirement(
                    name="vmlinux", description="Linux kernel symbols"),
                requirements.PluginRequirement(
                    name='pslist', plugin=pslist.PsList, version=(1, 0, 0)),
                requirements.PluginRequirement(
                    name='lsmod', plugin=lsmod.Lsmod, version=(1, 0, 0)),
                requirements.ListRequirement(name='time',
                                             description='Time interval for data checking',
                                             element_type=int,
                                             optional=True)]

    def get_processes(self):

        tasks = pslist.PsList.list_tasks(self.context,
                                         self.config['primary'],
                                         self.config['vmlinux'])

        for task in tasks:
            ppid = 0
            if task.parent:
                ppid = task.parent.pid
            task_name = utility.array_to_string(task.comm)

            yield [task.pid, ppid, task_name]

    def get_modules(self):

        for module in lsmod.Lsmod.list_modules(self.context,
                                        self.config['primary'],
                                        self.config['vmlinux']):

            mod_name = utility.array_to_string(module.name)

            yield [str(hex(module.vol.offset)), mod_name]

    def get_files(self):

        vmlinux = self.context.module(self.config["vmlinux"], "primary", 0)

        tasks = pslist.PsList.list_tasks(self.context,
                                         self.config['primary'],
                                         self.config['vmlinux'])

        for task in tasks:
            try:
                fd_table = task.files.get_fds()
                max_fds = task.files.get_max_fds()

                if fd_table == 0:
                    continue

                file_type = self.config['vmlinux'] + constants.BANG + 'file'

                fds = objects.utility.array_of_pointers(
                    fd_table, count=max_fds, subtype=file_type, context=self.context)

                for (fd_num, filp) in enumerate(fds):

                    if filp != 0:
                        file = vmlinux.object('file', offset=filp)
                        ppid = 0
                        if task.parent:
                            ppid = task.parent.pid
                        task_name = "%d/%d/%s" % (
                            task.pid, ppid, utility.array_to_string(task.comm))
                        yield (file, task_name)

            except exceptions.PagedInvalidAddressException:
                pass
            except exceptions.InvalidAddressException:
                pass

    def get_connections(self):

        vmlinux = self.context.module(self.config["vmlinux"], "primary", 0)
        sfop = vmlinux.get_symbol("socket_file_ops").address
        dfop = vmlinux.get_symbol("sockfs_dentry_operations").address

        for (file, task) in self.get_files():

            try:

                if hasattr(file, "f_dentry"):
                    dentry = file.f_dentry
                else:
                    dentry = file.f_path.dentry

                if file.f_op == sfop or dentry.d_op == dfop:
                    iaddr = file.f_inode

                    # has to get the struct socket given an inode
                    socket_type = vmlinux.get_type("socket")
                    backsize = socket_type.size
                    addr = iaddr - backsize
                    skt = vmlinux.object('socket', offset=addr)

                    inet_sock = vmlinux.object("inet_sock", offset=skt.sk)

                    protocols = self._get_constants('IPPROTO_')

                    if inet_sock.sk.sk_protocol in protocols.keys():

                        prot_name = protocols[inet_sock.sk.sk_protocol].replace(
                            "IPPROTO_", "")
                        sk_common = inet_sock.sk.__getattr__("__sk_common")
                        state = self.linux_tcp_states[sk_common.skc_state] if inet_sock.sk.sk_protocol == socket.IPPROTO_TCP else ""

                        family = sk_common.skc_family

                        if family == socket.AF_UNIX:
                                unix_sock = vmlinux.object(
                                    "unix_sock", offset=inet_sock.sk.vol.offset)

                                if unix_sock.addr:
                                    name_obj = vmlinux.object(
                                        "sockaddr_un", offset=unix_sock.addr.name.vol.offset)
                                    path_name = utility.array_to_string(
                                        name_obj.sun_path)
                                else:
                                    path_name = ""

                                yield [0, [prot_name, path_name, str(iaddr.i_ino), task]]

                        elif family in (socket.AF_INET, socket.AF_INET6, 10, 30):
                            saddr = self._get_address(
                                addr=inet_sock.inet_saddr, family=family)
                            sport = self._get_port(inet_sock.inet_sport)

                            daddr = self._get_address(
                                addr=sk_common.skc_daddr, family=family) if hasattr(
                                    sk_common, "skc_daddr") else ""

                            dport = self._get_port(sk_common.skc_dport) if hasattr(
                                sk_common, "skc_dport") else ""

                            if daddr == "" and dport == "":
                                addr_path = "%s:%s" % (
                                    saddr, sport)
                            else:
                                addr_path = "%s:%s > %s:%s" % (
                                    saddr, sport, daddr, dport)

                            yield [1, [prot_name, str(addr_path), state, task]]

            except exceptions.PagedInvalidAddressException:
                pass
            except exceptions.InvalidAddressException:
                pass

    def _get_constants(self, prefix):
        """Create a dictionary mapping socket module constants to their names."""
        return dict((getattr(socket, n), n)
                    for n in dir(socket)
                    if n.startswith(prefix)
                    )

    def _get_address(self, addr, family):

        if family == socket.AF_INET:
            return str(ipaddress.IPv4Address(addr).reverse_pointer).replace(".in-addr.arpa", "")
        elif family == socket.AF_INET6:
            return str(ipaddress.IPv6Address(addr).reverse_pointer).replace(".ip6.arpa", "")
        else:
            return addr

    def _get_port(self, port):
        return int.from_bytes(port.to_bytes(2, 'little'), 'big')

    def _delete_duplicates(self, l):
        l.sort()
        return list(l for l, _ in itertools.groupby(l))

    def _clear(self): print("\033c", end="")

    def _update_data(self):
        ml = self.context.layers["memory_layer"]
        ml.__init__(ml.context, ml.config_path, ml.name)

        pl = self.context.layers["primary"]
        pl.read.cache_clear()

        processes = list(self.get_processes())
        processes = self._delete_duplicates(processes)
        modules = list(self.get_modules())
        modules = self._delete_duplicates(modules)

        unix_connections = []
        inet_connections = []

        connections = list(self.get_connections())
        connections = self._delete_duplicates(connections)

        for con in connections:
            if con[0] == 0:
                unix_connections.append(con[1])
            elif con[0] == 1:
                inet_connections.append(con[1])

        return {
            'processes': processes,
            'modules': modules,
            'unix_connections': unix_connections,
            'inet_connections': inet_connections
        }

    def run(self):

        time_l = self.config.get('time')
        data = self._update_data()

        self._clear()

        print("\n")
        print("Please, wait ...")
        print("\n")

        if (len(time_l) > 0):

            time_interval = time_l[0]

            while(True):

                time.sleep(time_interval)
                self._clear()

                data_new = self._update_data()

                print("\n")
                print("Kernel modules (offset, name):")
                print("\n")
                mods_min = filter(
                    lambda x: x not in data_new["modules"], data["modules"])
                mods_plus = filter(
                    lambda x: x not in data["modules"], data_new["modules"])
                for mod in mods_min:
                    print('| (-) | {:<15}| {:<20}|'.format(
                        mod[0], mod[1]))
                for mod in mods_plus:
                    print('| (+) | {:<15}| {:<20}|'.format(
                        mod[0], mod[1]))

                print("\n")
                print("Processes (pid, ppid, name):")
                print("\n")
                procs_min = filter(
                    lambda x: x not in data_new["processes"], data["processes"])
                procs_plus = filter(
                    lambda x: x not in data["processes"], data_new["processes"])
                for proc in procs_min:
                    print('| (-) | {:<6}| {:<6}| {:<20}|'.format(
                        proc[0], proc[1], proc[2]))
                for proc in procs_plus:
                    print('| (+) | {:<6}| {:<6}| {:<20}|'.format(
                        proc[0], proc[1], proc[2]))

                print("\n")
                print(
                    "Active Internet connections (prot, address (src > dst), state, pid/ppid/process):")
                print("\n")
                incons_min = filter(
                    lambda x: x not in data_new["inet_connections"], data["inet_connections"])
                incons_plus = filter(
                    lambda x: x not in data["inet_connections"], data_new["inet_connections"])
                for i_con in incons_min:
                    print('| (-) | {:<6}| {:<55}| {:<12}| {:<25}|'.format(
                        i_con[0], i_con[1], i_con[2], i_con[3]))
                for i_con in incons_plus:
                    print('| (+) | {:<6}| {:<55}| {:<12}| {:<25}|'.format(
                        i_con[0], i_con[1], i_con[2], i_con[3]))

                print("\n")
                print(
                    "Active UNIX domain sockets (prot, path, inode, pid/ppid/process):")
                print("\n")
                uncons_min = filter(
                    lambda x: x not in data_new["unix_connections"], data["unix_connections"])
                uncons_plus = filter(
                    lambda x: x not in data["unix_connections"], data_new["unix_connections"])
                for u_con in uncons_min:
                    print('| (-) | {:<6}| {:<55}| {:<8}| {:<25}|'.format(
                        u_con[0], u_con[1], u_con[2], u_con[3]))
                for u_con in uncons_plus:
                    print('| (+) | {:<6}| {:<55}| {:<8}| {:<25}|'.format(
                        u_con[0], u_con[1], u_con[2], u_con[3]))

                print("\n")

                data = data_new

        else:
                self._clear()

                print("\n")
                print("Kernel modules (offset, name):")
                print("\n")
                for mod in data["modules"]:
                    print('| {:<15}| {:<20}|'.format(
                        mod[0], mod[1]))

                print("\n")
                print("Processes (pid, ppid, name):")
                print("\n")
                for proc in data["processes"]:
                    print('| {:<6}| {:<6}| {:<20}|'.format(
                        proc[0], proc[1], proc[2]))

                print("\n")
                print(
                    "Active Internet connections (prot, address (src > dst), state, pid/ppid/process):")
                print("\n")
                for i_con in data["inet_connections"]:
                    print('| {:<6}| {:<55}| {:<12}| {:<25}|'.format(
                        i_con[0], i_con[1], i_con[2], i_con[3]))

                print("\n")
                print(
                    "Active UNIX domain sockets (prot, path, inode, pid/ppid/process):")
                print("\n")
                for u_con in data["unix_connections"]:
                    print('| {:<6}| {:<55}| {:<8}| {:<25}|'.format(
                        u_con[0], u_con[1], u_con[2], u_con[3]))

                print("\n")

                return renderers.TreeGrid([("End", str)], [(0, [" "])])

