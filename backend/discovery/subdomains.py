import asyncio
import socket
import aiohttp
from typing import Optional

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'email',
    'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
    'mx1', 'mx2', 'mx3', 'mx4', 'mx5',
    'admin', 'administrator', 'root', 'sysadmin', 'webmaster',
    'api', 'app', 'apps', 'dev', 'staging', 'test', 'qa', 'uat', 'prod', 'preprod',
    'beta', 'alpha', 'demo', 'sandbox', 'internal', 'external',
    'portal', 'login', 'auth', 'sso', 'oauth', 'openid',
    'dashboard', 'console', 'panel', 'manage', 'management',
    'db', 'database', 'mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch',
    'git', 'github', 'gitlab', 'svn', 'ci', 'jenkins', 'build',
    'cdn', 'static', 'assets', 'media', 'images', 'img', 'css', 'js',
    'blog', 'wiki', 'forum', 'docs', 'documentation', 'help', 'support',
    'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
    'crm', 'erp', 'hr', 'finance', 'accounting', 'legal',
    'vpn', 'remote', 'rdp', 'ssh', 'sftp', 'scp',
    'monitor', 'monitoring', 'nagios', 'zabbix', 'grafana', 'prometheus',
    'backup', 'storage', 'nas', 'san', 'files', 'share',
    'proxy', 'reverse', 'loadbalancer', 'lb', 'haproxy', 'nginx',
    'mail2', 'mail3', 'smtp2', 'pop3', 'imap2',
    'cloud', 'aws', 'azure', 'gcp', 'digitalocean', 'heroku',
    'docker', 'kubernetes', 'k8s', 'openshift', 'rancher',
    'jenkins', 'nexus', 'artifactory', 'sonarqube',
    'jira', 'confluence', 'slack', 'teams', 'discord',
    'status', 'health', 'ping', 'uptime',
    'old', 'legacy', 'archive', 'new', 'next', 'v2', 'v3', 'v1',
    'm', 'mobile', 'wap', 'touch',
    'intranet', 'extranet', 'partner', 'vendor', 'client',
    'student', 'teacher', 'faculty', 'staff',
    'guest', 'public', 'private', 'secure',
    'ssl', 'tls', 'cert', 'pki', 'ca',
    'voip', 'sip', 'pbx', 'phone', 'call',
    'camera', 'cctv', 'dvr', 'nvr', 'surveillance',
    'printer', 'print', 'scanner',
    'iot', 'sensor', 'gateway', 'hub',
    'home', 'office', 'hq', 'branch',
    'us', 'eu', 'asia', 'uk', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'au',
    'east', 'west', 'north', 'south', 'central',
    'primary', 'secondary', 'tertiary',
    'master', 'slave', 'replica', 'mirror',
    'cache', 'memcache', 'varnish',
    'solr', 'lucene', 'kibana', 'logstash',
    'rabbitmq', 'kafka', 'activemq', 'zeromq',
    'graphql', 'rest', 'soap', 'grpc', 'websocket',
    'graphql-api', 'rest-api', 'soap-api',
    'auth-api', 'user-api', 'data-api', 'search-api',
    'analytics', 'tracking', 'metrics', 'stats',
    'report', 'reports', 'export', 'import',
    'feed', 'rss', 'atom', 'sitemap', 'robots',
    'newsletter', 'subscribe', 'unsubscribe',
    'survey', 'feedback', 'review', 'rating',
    'event', 'events', 'calendar', 'schedule',
    'ticket', 'tickets', 'booking', 'reservation',
    'job', 'jobs', 'career', 'careers', 'apply',
    'press', 'news', 'media', 'pr',
    'about', 'contact', 'terms', 'privacy', 'policy',
    'faq', 'tos', 'eula', 'license',
    'download', 'downloads', 'upload', 'uploads',
    'ftp2', 'sftp2', 'ssh2', 'telnet',
    'ldap', 'ldaps', 'ad', 'active-directory', 'domain',
    'radius', 'tacacs', 'kerberos', 'ntlm',
    'ntp', 'dhcp', 'dns', 'dhcp2',
    'syslog', 'log', 'logs', 'audit',
    'backup2', 'backup3', 'dr', 'disaster-recovery',
    'failover', 'hot-standby', 'warm-standby',
    'edge', 'origin', 'pop', 'edge1', 'edge2',
    'core', 'access', 'distribution', 'aggregation',
    'firewall', 'fw', 'fw1', 'fw2', 'utm', 'ids', 'ips',
    'waf', 'ids1', 'ids2', 'ips1', 'ips2',
    'siem', 'soc', 'noc', 'it', 'helpdesk',
    'ticketing', 'servicedesk', 'asset', 'inventory',
    'config', 'cmdb', 'patch', 'update', 'upgrade',
    'deploy', 'deployment', 'release', 'rollback',
    'pipeline', 'workflow', 'automation', 'orchestration',
    'terraform', 'ansible', 'puppet', 'chef', 'salt',
    'consul', 'vault', 'nomad', 'boundary',
    'etcd', 'zookeeper', 'redis-sentinel', 'redis-cluster',
    'cassandra', 'couchdb', 'couchbase', 'dynamodb',
    'neo4j', 'orientdb', 'arangodb', 'rethinkdb',
    'influxdb', 'timescaledb', 'clickhouse', 'druid',
    'pinot', 'presto', 'trino', 'spark', 'hadoop',
    'hive', 'pig', 'sqoop', 'oozie', 'airflow',
    'luigi', 'prefect', 'dagster', 'dbt',
    'mlflow', 'kubeflow', 'sagemaker', 'vertex',
    'tensorboard', 'wandb', 'comet', 'neptune',
    'dvc', 'clearml', 'guild', 'sacred',
    'optuna', 'ray', 'dask', 'joblib',
    'scikit', 'tensorflow', 'pytorch', 'jax',
    'onnx', 'triton', 'tensorrt', 'openvino',
    'coreml', 'tflite', 'ncnn', 'mnn',
    'mediapipe', 'opencv', 'pillow', 'scipy',
    'numpy', 'pandas', 'polars', 'dask',
    'modin', 'vaex', 'datatable', 'cudf',
]


class SubdomainEnumerator:
    def __init__(self, domain: str, wordlist: list = None, timeout: float = 2.0, max_concurrency: int = 100):
        self.domain = domain
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._results = []
        self._stop = False

    async def _check_subdomain(self, subdomain: str) -> Optional[dict]:
        if self._stop:
            return None
        async with self._semaphore:
            if self._stop:
                return None
            host = f"{subdomain}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                start = __import__('time').perf_counter()
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                latency = (__import__('time').perf_counter() - start) * 1000
                result = {'subdomain': host, 'ip': ip, 'latency': round(latency, 2)}
                try:
                    ptr = await loop.run_in_executor(None, socket.getfqdn, ip)
                    result['ptr'] = ptr
                except:
                    pass
                return result
            except (socket.gaierror, socket.herror, OSError):
                return None

    async def _check_crtsh(self) -> list:
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%25.{self.domain}&output=json",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        seen = set()
                        for entry in data:
                            name = entry.get('name_value', '')
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub.endswith(self.domain) and sub != self.domain and sub not in seen and '*' not in sub:
                                    seen.add(sub)
                                    results.append(sub)
        except Exception:
            pass
        return results

    async def _check_virustotal(self) -> list:
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40",
                    headers={'User-Agent': 'VOIS-Scanner/3.0'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('data', []):
                            sub = item.get('id', '')
                            if sub.endswith(self.domain):
                                results.append(sub)
        except Exception:
            pass
        return results

    async def enumerate(self, use_api: bool = True) -> list:
        all_subdomains = set(self.wordlist)
        if use_api:
            crtsh = await self._check_crtsh()
            vt = await self._check_virustotal()
            all_subdomains.update(crtsh)
            all_subdomains.update(vt)

        tasks = [asyncio.create_task(self._check_subdomain(s)) for s in all_subdomains]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result and not self._stop:
                self._results.append(result)

        return sorted(self._results, key=lambda x: x['subdomain'])

    def stop(self):
        self._stop = True


class DNSBruteForcer:
    def __init__(self, domain: str, wordlist: list = None, timeout: float = 2.0, max_concurrency: int = 200):
        self.domain = domain
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._results = []
        self._stop = False

    async def _check(self, subdomain: str) -> Optional[dict]:
        if self._stop:
            return None
        async with self._semaphore:
            if self._stop:
                return None
            host = f"{subdomain}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                start = __import__('time').perf_counter()
                ip = await loop.run_in_executor(None, socket.gethostbyname, host)
                latency = (__import__('time').perf_counter() - start) * 1000
                return {'subdomain': host, 'ip': ip, 'latency': round(latency, 2)}
            except (socket.gaierror, socket.herror, OSError):
                return None

    async def brute_force(self) -> list:
        tasks = [asyncio.create_task(self._check(s)) for s in self.wordlist]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result and not self._stop:
                self._results.append(result)
        return sorted(self._results, key=lambda x: x['subdomain'])

    def stop(self):
        self._stop = True
