(define (problem network-prob)
(:domain network_final)
(:objects 
unrestricted_file_upload executable_extension server_dot_c SQLInjection crafted-http-request - file
Arbitrary_code_web arbitrary_dns_code arbitrary_sql_commands arbitrary_code_ftp - code
access_web_server access_admin_server access_FTP_Server access_Database access_DNS_Server - accesstoken
longpath - pathname
stack-based heap-based-buffer-overflow - buffer
v2-7-8 windows-server-2012-gold v2-3 before-2-0-6 v3-1-1 v4-8 before-v13-0-12 - version
crafted-dns-response - response
cpsmysqlusermanager dnsmasq Ganglia microsoft-windows-8 simple-machines-forum Torguard-VPN GitLab-Runner - software
login_page - loginpage
Shared-Runner - environment
Malicious-Server - malserver
dockerd - daemon
Sensitive_Credentials - admindata
HTTP_sys - config
avatar_upload_functionality - functionality
gmetad - path
process-path - function
attacker1 - adversary
unspecified_directory - location
direct-request - request
DOS_Attack Server-Side-Request-Forgery - attack
internet - connection
Web-Server-1 - webserver
Database-Server-1 - sqlserver
FTP-Server-1 - ftpserver
Admin-Server-1 - adminserver
DNS-Server-1 - dnsserver
)
(:INIT 
(ftp-code arbitrary_code_ftp)
(ftp-version before-2-0-6)
(web-version windows-server-2012-gold)
(dns-code arbitrary_dns_code)
(request-ftp direct-request)
(sql-daemon dockerd)
(access-admin access_admin_server)
(admin-function process-path)
(sql-file sqlinjection)
(information sensitive_credentials)
(remote-access internet)
(configuration http_sys)
(web-code arbitrary_code_web)
(ftp-file unrestricted_file_upload)
(admin-attack dos_attack)
(attacker attacker1)
(web-server web-server-1)
(ftp-software simple-machines-forum)
(admin-path gmetad)
(exe-file executable_extension)
(admin-software ganglia)
(sql-attack server-side-request-forgery)
(access-dns access_dns_server)
(buffer-overflow heap-based-buffer-overflow)
(admin-version v3-1-1)
(ftp-functionality avatar_upload_functionality)
(admin-server admin-server-1)
(sql-env shared-runner)
(sql-code arbitrary_sql_commands)
(access-ftp access_ftp_server)
(directory unspecified_directory)
(sql-software-2 gitlab-runner)
(dns-attack dos_attack)
(admin-software-2 torguard-vpn)
(admin-file server_dot_c)
(dns-server dns-server-1)
(access-db access_database)
(login-page login_page)
(ftp-server ftp-server-1)
(sql-server database-server-1)
(has-connected web-server-1 database-server-1 admin-server-1 ftp-server-1 dns-server-1)
(sql-version-2 before-v13-0-12)
(dns-version v2-7-8)
(sql-malicious-server malicious-server)
(sql-version v2-3)
(longpath longpath)
(sql-software cpsmysqlusermanager)
(access-web access_web_server)
(response-dns crafted-dns-response)
(web-file crafted-http-request)
(web-software microsoft-windows-8)
(buffer-overflow stack-based)
(dns-software dnsmasq)
(admin-version-2 v4-8)
)
(:goal 
(and
(compromised-admin-server admin-server-1)
)
)
)
