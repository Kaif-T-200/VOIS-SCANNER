import asyncio
import hashlib
import time
from typing import Optional

# Conservative default credentials - only common/default ones
COMMON_PASSWORDS = [
    'password', '123456', 'admin', 'root', 'toor', 'test', 'guest',
    'default', '12345', '123123', 'pass', 'admin123', 'password123',
]

SSH_USERS = ['root', 'admin', 'user', 'ubuntu', 'ec2-user']
FTP_USERS = ['anonymous', 'admin']  # Removed 'ftp' - rarely used


class BruteForceEngine:
    """
    Conservative brute-force testing for common default credentials.
    WARNING: Only for authorized testing on your own systems!
    """
    
    def __init__(self, target: str, timeout: float = 3.0, max_concurrency: int = 5):
        self.target = target
        self.timeout = timeout
        self.max_concurrency = min(max_concurrency, 5)  # Cap at 5 concurrent
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._stop = False
        self._results = []

    async def brute_ssh(self, users: list = None, passwords: list = None, max_attempts: int = 25) -> list:
        """Test SSH with common credentials - LIMITED to prevent account lockout."""
        users = users or SSH_USERS
        passwords = passwords or COMMON_PASSWORDS
        results = []
        
        # Limit total attempts to prevent lockout
        attempts = 0
        max_attempts = min(max_attempts, 25)
        
        for user in users[:5]:  # Limit users tested
            for pwd in passwords[:5]:  # Limit passwords tested
                if self._stop or attempts >= max_attempts:
                    return results
                
                attempts += 1
                try:
                    import paramiko
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(self.target, username=user, password=pwd, timeout=self.timeout, allow_agent=False, look_for_keys=False)
                    results.append({'user': user, 'password': pwd, 'service': 'ssh'})
                    client.close()
                    print(f"[!] SSH: Found credential {user}:{pwd}")
                    return results  # Return on first success
                except Exception:
                    pass
        
        return results

    async def brute_ftp(self, users: list = None, passwords: list = None, max_attempts: int = 10) -> list:
        """Test FTP with common credentials - LIMITED."""
        users = users or FTP_USERS
        passwords = passwords or COMMON_PASSWORDS
        results = []
        
        attempts = 0
        for user in users[:3]:
            for pwd in passwords[:3]:
                if self._stop or attempts >= max_attempts:
                    return results
                
                attempts += 1
                try:
                    from ftplib import FTP, all_errors
                    ftp = FTP(timeout=self.timeout)
                    ftp.connect(self.target, timeout=self.timeout)
                    ftp.login(user, pwd)
                    ftp.quit()
                    results.append({'user': user, 'password': pwd, 'service': 'ftp'})
                    print(f"[!] FTP: Found credential {user}:{pwd}")
                    return results
                except Exception:
                    pass
        
        return results

    def stop(self):
        self._stop = True

        ftp.quit()

    async def brute_http_basic(self, users: list = None, passwords: list = None) -> list:
        import aiohttp
        users = users or HTTP_USERS
        passwords = passwords or COMMON_PASSWORDS
        results = []
        for user in users:
            for pwd in passwords:
                if self._stop:
                    return results
                try:
                    auth = aiohttp.BasicAuth(user, pwd)
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f'http://{self.target}', auth=auth, timeout=aiohttp.ClientTimeout(total=self.timeout), ssl=False) as resp:
                            if resp.status != 401:
                                results.append({'user': user, 'password': pwd, 'service': 'http_basic'})
                except Exception:
                    pass
        return results

    async def run(self, services: list = None) -> list:
        services = services or ['ssh', 'ftp', 'http_basic']
        tasks = []
        if 'ssh' in services:
            tasks.append(self.brute_ssh())
        if 'ftp' in services:
            tasks.append(self.brute_ftp())
        if 'http_basic' in services:
            tasks.append(self.brute_http_basic())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_results = []
        for r in results:
            if isinstance(r, list):
                all_results.extend(r)
        return all_results

    def stop(self):
        self._stop = True
