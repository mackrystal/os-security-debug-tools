import win32con
import win32api
import win32security

import wmi
import os
import sys

def get_proces_privileges(pid):
	try:
		#Creating process handler by process PID
		hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, pid)
		
		#Opening handler to process token
		htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
		
		#Getting token information
		privs = win32security.GetTokenInformation(htok, win32security.TokenPrivileges)
		
		priv_list = []
		for i in privs:
			if i[1] == 3:
				priv_list += "{}|".format(win32security.LookupPrivilegeName(None,i[0]))
				
		priv_name = "".join([str(i) for i in priv_list])
	except:
		priv_name = "N/A"
	
	return priv_name 

def log_to_file(message):
	fd = open("process_monitor_log.csv", "ab")
	fd.write(b"message")
	fd.write(b"\r\n")
	fd.close()
	
	return
	
#Including log message header
log_to_file("Time,User,Executable,CommandLine,PID,Parent PID,Privileges")

#creating wmi interface
c = wmi.WMI ()

#Creating process monitor
process_watcher = c.Win32_Process.watch_for("Creation")

while True:
	try:
		new_process = process_watcher()
		
		procOwner = new_process.GetOwner()
		procOwner = "{}\\{}".format(procOwner[0],procOwner[2])
		create_date = new_process.CreationDate
		executable = new_process.ExecutablePath
		cmdline = new_process.CommandLine
		pid = new_process.ProcessId
		parentPid = new_process.ParentProcessId
		
		privileges = get_proces_privileges(pid)
		
		process_log_message = ("{}, {}, {}, {}, {}, {}, {}\r\n".format(create_date, procOwner, executable, cmdline, pid, parentPid, privileges))
		
		print(process_log_message)
		
		log_to_file(process_log_message)
	except:
		pass
