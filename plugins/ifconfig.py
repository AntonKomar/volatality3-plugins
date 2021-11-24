from typing import List
import ipaddress

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist



class Loctime(interfaces.plugins.PluginInterface):
    """Target system local time."""

    _required_framework_version = (1, 0, 0)

    _version = (1, 0, 0)

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
                requirements.ListRequirement(name='pid',
                                             element_type=int,
                                             description="Process IDs to include (all other processes are excluded)",
                                             optional=True)]

    def _generator(self):

        vmlinux = self.context.module(self.config["vmlinux"], "primary", 0)

        nets = vmlinux.object_from_symbol(
            symbol_name="net_namespace_list").cast("list_head")

        l = nets.to_list(self.config["vmlinux"]+"!net", "list")

        for net in l:

            dbh = net.dev_base_head
            netdevices = dbh.to_list(
                self.config["vmlinux"]+"!net_device", "dev_list")

            for dev in netdevices:

                dev_ip = vmlinux.object("in_device", offset=dev.ip_ptr)

                dev_ip_if = vmlinux.object("in_ifaddr", offset=dev_ip.ifa_list)

                while(dev_ip_if != 0):

                    label = str("".join(map(chr,dev_ip_if.ifa_label)))
                    addr = str(ipaddress.IPv4Address(
                        dev_ip_if.ifa_address).reverse_pointer)

                    yield (0, (label, addr))

                    if(dev_ip_if.ifa_next != 0):
                        dev_ip_if = vmlinux.object(
                            "in_ifaddr", offset=dev_ip_if.ifa_next)
                    else:
                        dev_ip_if = 0

                    
                
                   
            
    def run(self):
        
        return renderers.TreeGrid([("Name", str), ("Inet addr", str)],
                                  self._generator())
