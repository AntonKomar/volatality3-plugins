# volatality3-plugins

netcon.py is a simple intrusion detection/analysis tool that can extract information about running processes, loaded kernel modules, network connections using virtual machine introspection with volatality3.

The tool extracts the information every RUNINTERVAL seconds (configurable), and
displays new and missing entries compared to the previous run. 

Example output:

	Processes (pid, ppid, name):
	+ 16239 1377 sshd
	+ 16276 16239 bash
	+ 16289 16276 top
	
	Kernel modules (offset, name):
	- 0xffffc054ab40 floppy
	+ 0xffffc0010180 md4
	
	Network sockets:
	+ tcp 192.168.13.214:22 > 10.42.0.2:56553 1377/sshd
	
	
To run the plugin type the command with defined dump file location:

```shell
python3 volatility3/vol.py -f dump_location linux.netcon
```

Or you can run the shell script with the command:

```shell
./vmidet.sh $dump_name $time_interval
```

But before it you need to run:
```shell
chmod +x ./vmidet.sh
```

## Requirements

- Python 3.5.3 or later. <https://www.python.org>
- Pefile 2017.8.1 or later. <https://pypi.org/project/pefile/>
- Volatility3. <https://github.com/volatilityfoundation/volatility3>

## Downloading Volatility

The plugin requires volatality3 framework installed in order to work. The file “netcon.py” has to be located in “/volatility3/volatality3/plugins/linux” folder. It is required to run the plugin by “volatility” tool. You can get the latest version of the volatality using the following command:

```shell
git clone https://github.com/volatilityfoundation/volatility3.git
```
