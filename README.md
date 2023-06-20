# os-security-debug-tools

1. Token_impersonation tool:

Help me to impersonate to windows elevated privileges. When you want impersonate to NT_AUTHORITY/SYSTEM, just use:


2. Process Hook Monitor:

Great tool to monitor windows API handlers and identify dangerous process. 
Processes with permissions like: SeBackupPrivilege, SeDebug, SeLoadDriver can be potentialy compromise and used to privileges escalation.
Simply start python script without parameters and collect data in readable csv format.
