# fix debug output, not seeing enough info "or any info"

from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp
from lib.scripts.reg import RemoteOperations
from lib.logger import logger
from requests.exceptions import RequestException
from tabulate import tabulate
from getpass import getpass
import ntpath
import os
import pandas as dp
import requests
import socket
import sqlite3
import threading

class SMB:
    
    def __init__(self, username=None, password=None, domain=None, target_dom=None,
                    dc_ip=None,ldaps=False, kerberos=False, no_pass=False, hashes=None,
                    aes=None, debug=False, save=False,
                    logs_dir=None, skip_reg=False, http_timeout=5, smb_timeout=30,
                    skip_mssql=False, mssql_timeout=5):
        self.username = username
        self.password = password
        self.domain = domain
        self.target_dom = target_dom
        self.dc_ip = dc_ip
        self.ldaps = ldaps
        self.kerberos = kerberos
        self.no_pass = no_pass
        self.aes = aes
        self.save = save
        self.logs_dir = logs_dir
        self.debug = debug
        self.skip_reg = skip_reg
        self.http_timeout = http_timeout
        self.smb_timeout = smb_timeout
        self.skip_mssql = skip_mssql
        self.mssql_timeout = mssql_timeout
        self.ldap_session = None
        self.search_base = None
        self.test_array = []
        self.hashes=hashes
        self.lmhash = ""
        self.nthash = ""
        if self.hashes:
            self.lmhash, self.nthash = self.hashes.split(':')
        self.database = f"{logs_dir}/db/find.db"
        self.conn = sqlite3.connect(self.database, check_same_thread=False)

    def run(self):
        #TODO add check to be sure FIND module was run
        self.check_siteservers()
        self.check_managementpoints()
        self.check_distributionpoints()
        self.check_computers()
        self.conn.close()

    def printlog(self, servers):
        filename = (f'{self.logs_dir}/smbhunter.log')
        logger.info(f'[+] Results saved to {filename}')
        for server in servers:
            with open(filename, 'a') as f:
                f.write("{}\n".format(server))
                f.close
        return



    def check_remote_dbs(self, db_servers):
        cursor = self.conn.cursor()
        for db in db_servers:
            mssql = self.mssql_check(db)
            cursor.execute('''select * from SiteDatabases where Hostname = ?''', (db,))
            exists = cursor.fetchone()
            if not exists:
                cursor.execute('''insert into SiteDatabases (Hostname, MSSQL) values (?,?)''', 
                            (db, str(mssql)))
            else:
                logger.debug(f"[*] Skipping already known host: {db}")

        return
        
        

    def remote_reg_find_db(self, hostname, conn):
        #  Manuel Porto (@manuporto)
        #  Alberto Solino (@agsolino)
        #  thanks to ^ for reg.py
        db_servers = []
        keyName = r"HKLM\SOFTWARE\Microsoft\SMS\components\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers"
        logger.info(f"[*] Querying remote registry of {hostname}")
        self.__remoteOps = RemoteOperations(conn, self.kerberos, self.dc_ip)
        try:
            self.__remoteOps.enableRegistry()
        except Exception as e:
            logger.debug(str(e))
            logger.debug('Cannot check RemoteRegistry status. Triggering start trough named pipe...')
            self.__remoteOps.triggerWinReg()
            self.__remoteOps.connectWinReg()
        try:
            dce = self.__remoteOps.getRRP()
            hRootKey, subKey = self.__remoteOps.strip_root_key(dce, keyName)
            ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey,
                                    samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)
            
            #self.__remoteOps.print_key_values(dce, ans2['phkResult'])
            i = 0
            while True:
                try:
                    key = rrp.hBaseRegEnumKey(dce, ans2['phkResult'], i)
                    db = (key['lpNameOut'][:-1])
                    logger.info(f"[*] Found potential remote database server: {db}")
                    db_servers.append(db)
                    i += 1
                except Exception as e:
                    break
        except (Exception, KeyboardInterrupt) as e:
            #import traceback
            #traceback.print_exc()
            logger.info(e)
        finally:
            if self.__remoteOps:
                self.__remoteOps.finish()
        if db_servers:
            self.check_remote_dbs(db_servers)
        #done with remote registry stuff
        return 


    #treat all computers with full control as siteservers and active
    #if default file shares are missing implies the use of high availability
    #which means it's possibly a passive site server that still retains the same
    #privileges
    def check_siteservers(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM SiteServers WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        cursor.execute("SELECT * FROM CAS")
        cas = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} site servers.")
            for idx, i in enumerate(hostnames, start=1):
                hostname = (i[0])
                cas_sitecode = False
                logger.info(f"[*] ({idx}/{len(hostnames)}) Profiling site server {hostname}")
                #only enumerate if the host is reachable
                conn = self.smb_connection(hostname)
                if conn:
                    #see if we can query remote registry for the site database
                    if self.skip_reg:
                        logger.debug(f"[*] -skip-reg set; skipping remote registry enumeration on {hostname}")
                    else:
                        logger.debug(f"[*] Step: remote registry on {hostname}")
                        potential_dbs = self.remote_reg_find_db(hostname, conn)
                    logger.debug(f"[*] Step: SMB share enumeration on {hostname}")
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    #check if mssql is self hosted
                    logger.debug(f"[*] Step: MSSQL check on {hostname}")
                    mssql = self.mssql_check(hostname)
                    #check for SMS provider roles
                    logger.debug(f"[*] Step: SMS provider check on {hostname}")
                    provider = self.provider_check(hostname)
                    #check if fileshares are on 
                    if siteserv:
                        status = "Active" 
                    else:
                        status = "Passive"

                    for i in cas:
                        if site_code in i:
                            cas_sitecode = True

                    cursor.execute(f'''Update SiteServers SET SiteCode=?, CAS=?, SigningStatus=?, SiteServer=?, SMSProvider=?, Config=?, MSSQL=? WHERE Hostname=?''',
                                (str(site_code), str(cas_sitecode), str(signing), "True", str(provider), str(status), str(mssql), hostname))
                else:
                    cursor.execute(f'''Update SiteServers SET SiteCode=?, CAS=?, SigningStatus=?, SiteServer=?, Config=?, MSSQL=? WHERE Hostname=?''',
                                ("Connection Failed", "", "", "True", "", "", hostname))

                self.conn.commit()
            logger.info("[+] Finished profiling Site Servers.")
            cursor.close()
            tb_ss = dp.read_sql("SELECT * FROM SiteServers WHERE Hostname IS NOT 'Unknown' ", self.conn).fillna('')
            tb_db = dp.read_sql("SELECT * FROM SiteDatabases WHERE Hostname IS NOT 'Unknown' ", self.conn).fillna('')
            logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
            logger.info("[+] Finished profiling potential Site Databases.")
            logger.info(tabulate(tb_db, showindex=False, headers=tb_db.columns, tablefmt='grid'))
        else:
            logger.info("[-] No SiteServers found in database.")
        return

    #check for signing status on management points
    def check_managementpoints(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM ManagementPoints WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
                #logger.info(f"Profling {len(cas)} site servers.")
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} management points.")
            for idx, i in enumerate(hostnames, start=1):
                hostname = i[0]
                logger.info(f"[*] ({idx}/{len(hostnames)}) Profiling management point {hostname}")
                conn = self.smb_connection(hostname)
                if conn:
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    cursor.execute(f'''Update ManagementPoints SET SigningStatus=? WHERE Hostname=?''',
                                (str(signing), hostname))
                self.conn.commit()

            logger.info("[+] Finished profiling Management Points.")
            cursor.close()
            tb_mp = dp.read_sql("SELECT * FROM ManagementPoints WHERE Hostname IS NOT 'Unknown' ", self.conn).fillna('')
            logger.info(tabulate(tb_mp, showindex=False, headers=tb_mp.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No Management Points found in database.")

    def check_distributionpoints(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM PXEDistributionPoints WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} distribution points.")
            for idx, i in enumerate(hostnames, start=1):
                hostname = i[0]
                logger.info(f"[*] ({idx}/{len(hostnames)}) Profiling distribution point {hostname}")
                conn = self.smb_connection(hostname)
                if conn:
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    #Hostname, SigningStatus, SCCM, WDS
                    cursor.execute(f'''Update PXEDistributionPoints SET SigningStatus=?, SCCM=?, WDS=? WHERE Hostname=?''',
                                (str(signing), str(sccmpxe), str(wdspxe), hostname))
                self.conn.commit()

            logger.info("[+] Finished profiling Distribution Points.")
            cursor.close()
            tb_dp = dp.read_sql("SELECT * FROM PXEDistributionPoints WHERE Hostname IS NOT 'Unknown' ", self.conn).fillna('')
            logger.info(tabulate(tb_dp, showindex=False, headers=tb_dp.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No Management Points found in database.")
    
    #read from computers table created from strings check in LDAP module
    def check_computers(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT Hostname FROM Computers WHERE Hostname IS NOT 'Unknown'")
        hostnames = cursor.fetchall()
        if hostnames:
            logger.info (f"Profiling {len(hostnames)} computers.")
            for idx, i in enumerate(hostnames, start=1):
                hostname = i[0]
                logger.info(f"[*] ({idx}/{len(hostnames)}) Profiling computer {hostname}")
                conn = self.smb_connection(hostname)
                if conn:
                    logger.debug(f"[*] Step: MSSQL check on {hostname}")
                    mssql = self.mssql_check(hostname)
                    logger.debug(f"[*] Step: HTTP MP check on {hostname}")
                    mp = self.http_check(hostname)
                    logger.debug(f"[*] Step: SMS provider check on {hostname}")
                    provider = self.provider_check(hostname)
                    logger.debug(f"[*] Step: SMB share enumeration on {hostname}")
                    signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe = self.smb_hunter(hostname, conn)
                    if site_code == 'None':
                        try:
                            cursor.execute(f"SELECT SiteCode FROM ManagementPoints WHERE Hostname IS '{hostname}'")
                            result = cursor.fetchall()
                            if not result:
                                site_code = 'None'
                            else:
                                site_code = result[0][0]
                        except:
                            pass
                    cursor.execute(f'''Update Computers SET SiteCode=?, SigningStatus=?, SiteServer=?, ManagementPoint=?, DistributionPoint=?, SMSProvider=?, WSUS=?, MSSQL=? WHERE Hostname=?''',
                                (str(site_code), str(signing), str(siteserv), str(mp), str(distp), str(provider), str(wsus), str(mssql), hostname))
                self.conn.commit()
            logger.info("[+] Finished profiling all discovered computers.")
            cursor.close()
            tb_ss = dp.read_sql("SELECT * FROM Computers WHERE Hostname IS NOT 'Unknown' ", self.conn).fillna('')
            logger.info(tabulate(tb_ss, showindex=False, headers=tb_ss.columns, tablefmt='grid'))
            return
        else:
            logger.info("[-] No computers found in database.")
    
    def smb_connection(self, server):
        try:
            if not (self.password or self.hashes or self.aes or self.no_pass):
                self.password = getpass("Password:")
            connect_timeout = 5
            if self.kerberos:
                logger.debug(f'[SMB] Connecting to {server}:445 | auth=Kerberos user={self.username} domain={self.domain} kdc={self.dc_ip}')
            elif self.hashes:
                logger.debug(f'[SMB] Connecting to {server}:445 | auth=NTLM(hash) user={self.domain}\\{self.username} lmhash={self.lmhash or "aad3..."} nthash={self.nthash[:8]}...')
            else:
                logger.debug(f'[SMB] Connecting to {server}:445 | auth=NTLM(password) user={self.domain}\\{self.username}')
            conn = SMBConnection(server, server, None, timeout=connect_timeout)
            if self.kerberos:
                conn.kerberosLogin(user=self.username, password=self.password, domain=self.domain, kdcHost=self.dc_ip)
            else:
                conn.login(user=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
            # apply read timeout to all subsequent SMB ops on this conn
            conn.setTimeout(self.smb_timeout)
            logger.debug(f"[+] Connected to smb://{server}:445")
            return conn
        except socket.error as e:
            logger.debug(f"[-] SMB socket error connecting to {server}:445 | {e}")
            return
        except Exception as e:
            logger.info(f"[-] SMB SessionError: {e}")
            logger.debug(f"[-] Failed: smb://{server}:445 user={self.domain}\\{self.username}")
            return

    #profile remote hosts based on default file shares configured on particular roles
    def smb_hunter(self, server, conn):
        pxe_boot_servers = []
        try:
            site_code = 'None'
            siteserv = False
            distp = False
            wsus = False
            wdspxe = False
            sccmpxe = False

            signing = conn.isSigningRequired()
            shares = conn.listShares()
            sharenames = [share['shi1_netname'][:-1] for share in shares]
            remarks = [share['shi1_remark'][:-1] for share in shares]
            shares_dict = dict(zip(sharenames, remarks)) 

            if "SMS_SITE" in shares_dict:
                try:
                    remark = shares_dict.get('SMS_DP$', '')
                    if 'ConfigMgr Site Server' in remark:
                        siteserv = True
                    sc = shares_dict.get("SMS_SITE", '')
                    if 'SMS Site' in sc:
                        site_code = (sc.split(" ")[2])
                except:
                    siteserv = False
            if "SMS_DP$" in shares_dict:
                try:
                    remark = shares_dict.get("SMS_DP$", '')
                    if "SMS Site" in remark:
                        distp = True
                        site_code = (remark.split(" ")[2])
                except:
                    distp = False
            if "REMINST" in shares_dict:
                #list REMINST contents to check if the SMSTemp dir actually exists
                remark = shares_dict.get("REMINST", '')
                if "Windows Deployment Services Share" in remark:
                    wdspxe = True
                if "RemoteInstallation" in remark:
                    sccmpxe = True
                try:
                    check = conn.listPath(shareName="REMINST", path="//*")
                    for i in check:
                        if i.get_longname() == "SMSTemp":
                            pxe_boot_servers.append(server)

                except SessionError as e:
                    if "STATUS_ACCESS_DENIED" in str(e):
                        logger.info("[!] Access Denied to the REMINST share.")
                    else:
                        logger.info("[!] SMB session error: {e}")

            if "WsusContent" in shares_dict:
                wsus = True


        
            if pxe_boot_servers:
                self.smb_spider(conn, pxe_boot_servers)
            return signing, site_code, siteserv, distp, wsus, wdspxe, sccmpxe
        except socket.error:
            logger.info(socket.error)
            return
        except Exception as e:
            logger.info(f"[-] {e}")
            return

    #if a distribution point is found with this directory
    #spider and search for pxeboot variables files
    def smb_spider(self, conn, targets):
        vars_files = []
        downloaded = []
        connect_timeout = 5
        for target in targets:
            try:
                if self.kerberos:
                    logger.debug(f'[SMB] spider: connecting to {target}:445 | auth=Kerberos user={self.username} domain={self.domain} kdc={self.dc_ip}')
                else:
                    logger.debug(f'[SMB] spider: connecting to {target}:445 | auth=NTLM user={self.domain}\\{self.username}')
                conn = SMBConnection(target, target, None, timeout=connect_timeout)
                if self.kerberos:
                    conn.kerberosLogin(user=self.username, password=self.password, domain=self.domain, kdcHost=self.dc_ip)
                else:
                    conn.login(user=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash)
                conn.setTimeout(self.smb_timeout)
                logger.info(f'[*] Searching {target} for PXEBoot variables files.')
                for shared_file in conn.listPath(shareName="REMINST", path="SMSTemp//*"):
                    if shared_file.get_longname().endswith('.var'):
                        # store full path for easy reporting
                        full_path = (f"\\\\{target}\\REMINST\\SMSTemp\\{shared_file.get_longname()}")
                        vars_files.append(full_path)
                        logger.debug(f"[+] Found {full_path}")
                        if self.save:
                            file_name = shared_file.get_longname()
                            with open(ntpath.basename(file_name), 'wb') as fh:
                                path = f"SMSTemp//{file_name}"
                                try:
                                    conn.getFile(shareName="REMINST",pathName = path, callback=fh.write)
                                    downloaded.append(file_name)
                                except Exception as e:
                                    logger.info(f"[-] {e}")
                    else:
                        return
            except Exception as e:
                logger.debug(e)
        conn.logoff()
        
        #these logs should stay
        if len(downloaded) > 0:
            logger.info("[+] Variables files downloaded!")
            for i in (downloaded):
                os.replace(f'{os.getcwd()}/{i}', f'{self.logs_dir}/loot/{i}')
        if vars_files:
            self.printlog(vars_files)
        

# Run fn() with a hard wall-clock timeout in a daemon thread. Needed because
# proxychains hooks connect() to handle SOCKS, which can bypass socket-level
# timeouts. Daemon thread can't be killed, but it won't block process exit.
    def _hard_timeout(self, fn, timeout, label, *args, **kwargs):
        result = {'val': None, 'err': None, 'done': False}
        def runner():
            try:
                result['val'] = fn(*args, **kwargs)
            except Exception as e:
                result['err'] = e
            finally:
                result['done'] = True
        t = threading.Thread(target=runner, daemon=True)
        t.start()
        t.join(timeout)
        if not result['done']:
            logger.debug(f"[-] {label} timed out after {timeout}s")
            return None
        if result['err']:
            logger.debug(f"[-] {label}: {result['err']}")
        return result['val']

#check if the target host is running MSSQL
#intention here is to help find the site database location or at least narrow it down
    def mssql_check(self, server):
        if self.skip_mssql:
            logger.debug(f"[*] -skip-mssql set; skipping MSSQL probe on {server}")
            return False
        def probe():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.mssql_timeout)
            try:
                sock.connect((f'{server}', 1433))
                return True
            except Exception as e:
                logger.debug(f"[-] mssql {server}: {e}")
                return False
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        result = self._hard_timeout(probe, self.mssql_timeout + 2, f"mssql_check {server}")
        return bool(result)
    
#check if the target host is hosting the SMS_MP directory
#intention here is to return whether the host has the Management Point role
    def http_check(self, server):
        result = self._hard_timeout(self._http_check_inner, (self.http_timeout * 4) + 2, f"http_check {server}", server)
        return bool(result)

    def _http_check_inner(self, server):
        try:
            endpoint = f"http://{server}/ccm_system_windowsauth/"
            r = requests.request("GET",
                                endpoint,
                                verify=False,
                                timeout=self.http_timeout)
            if r.status_code == 401:
                return True

            endpoint = f"https://{server}/ccm_system_windowsauth/"
            r = requests.request("GET",
                                endpoint,
                                verify=False,
                                timeout=self.http_timeout)
            if r.status_code == 401:
                return True
            endpoint = f"https://{server}/ccm_system_altauth/"
            r = requests.request("GET",
                                endpoint,
                                verify=False,
                                timeout=self.http_timeout)
            if r.status_code == 403:
                return True
            endpoint = f"https://{server}/ccm_system_altauth/request"
            r = requests.request("CCM_POST",
                                endpoint,
                                verify=False,
                                timeout=self.http_timeout)
            if r.status_code == 200:
                return True
            else:
                return False
        except RequestException as e:
            logger.debug(e)
            return False
        except Exception as e:
            logger.debug("An unknown error occurred")
            logger.debug(e)

#check if the target host is hosting the adminservice api
#intention here is to return whether the host is hosting the SMS
#Provider role
    def provider_check(self, server):
        result = self._hard_timeout(self._provider_check_inner, self.http_timeout + 2, f"provider_check {server}", server)
        return bool(result)

    def _provider_check_inner(self, server):
        try:
            endpoint = f"https://{server}/adminservice/wmi/"
            r = requests.request("GET",
                                endpoint,
                                verify=False,
                                timeout=self.http_timeout)
            if r.status_code == 401:
                return True
            else:
                return False
        except RequestException as e:
            logger.debug(e)
            return False
        except Exception as e:
            logger.debug("An unknown error occurred")
            logger.debug(e)
        return



