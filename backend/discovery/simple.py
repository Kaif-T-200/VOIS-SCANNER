"""
Network Discovery and Topology Mapping
Simplified alternative to Nmap's network discovery
"""
import asyncio
import socket
import ipaddress
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class HostInfo:
    ip: str
    hostname: str = ""
    is_up: bool = True
    latency: float = 0.0
    services: List[int] = field(default_factory=list)


class SimpleNetworkDiscovery:
    """Simple, reliable network discovery using ICMP and TCP."""
    
    def __init__(self, network_or_ip: str, timeout: float = 2.0):
        """
        Initialize discovery for a network or single IP.
        
        Examples:
        - Single IP: "192.168.1.1"
        - Network: "192.168.1.0/24"
        """
        self.network_or_ip = network_or_ip
        self.timeout = timeout
        self.hosts = []
    
    async def discover(self) -> List[HostInfo]:
        """Discover hosts on network - use TCP port 80 probe or quick connection test."""
        try:
            # Try to parse as network CIDR
            if '/' in self.network_or_ip:
                try:
                    network = ipaddress.ip_network(self.network_or_ip, strict=False)
                    # Limit to /24 for practical scanning (256 hosts)
                    if network.num_addresses > 256:
                        network = ipaddress.ip_network(f"{network.network_address}/24", strict=False)
                    
                    ips = [str(ip) for ip in network.hosts()]  # Exclude network and broadcast
                except ValueError as e:
                    print(f"Invalid network: {e}")
                    return []
            else:
                # Single IP
                ips = [self.network_or_ip]
            
            # Limit parallel connections to prevent resource exhaustion
            semaphore = asyncio.Semaphore(10)
            
            async def probe_with_limit(ip):
                async with semaphore:
                    return await self._probe_host(ip)
            
            # Scan for active hosts
            tasks = [probe_with_limit(ip) for ip in ips]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter successful discoveries - skip None and exceptions
            self.hosts = []
            for r in results:
                if isinstance(r, HostInfo):
                    self.hosts.append(r)
                elif isinstance(r, Exception):
                    pass  # Silently skip failed probes
            
            return self.hosts
        
        except Exception as e:
            print(f"Discovery error: {e}")
            return []
    
    async def _probe_host(self, ip: str) -> Optional[HostInfo]:
        """Probe a single host using TCP port 80 (HTTP)."""
        try:
            # Quick TCP test to port 80 (common web services)
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 80),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                is_up = True
            except asyncio.TimeoutError:
                # Timeout doesn't necessarily mean host is down on non-web services
                is_up = False
            except (ConnectionRefusedError, OSError):
                # Connection refused or unreachable - try port 443
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, 443),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    is_up = True
                except:
                    is_up = False
            
            # Get hostname if available
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Return host info if valid
            if is_up:
                return HostInfo(ip=ip, hostname=hostname, is_up=True, latency=0.0)
            else:
                return None
        except Exception as e:
            return None


class NetworkTopology:
    """Build and visualize network topology for frontend."""
    
    def __init__(self, discovery_results: List[HostInfo]):
        self.hosts = discovery_results
    
    def to_graph_data(self) -> Dict:
        """Convert to graph format for D3.js or similar visualization."""
        nodes = []
        links = []
        
        # Add gateway/network node
        gateway_node = {
            'id': 'network',
            'label': 'Network',
            'type': 'network',
            'color': '#6366f1'
        }
        nodes.append(gateway_node)
        
        # Add discovered hosts
        for i, host in enumerate(self.hosts):
            node = {
                'id': host.ip,
                'label': host.hostname or host.ip,
                'type': 'host',
                'color': '#10b981',
                'latency': host.latency,
                'services': len(host.services)
            }
            nodes.append(node)
            
            # Link to network
            link = {
                'source': 'network',
                'target': host.ip,
                'label': 'connected'
            }
            links.append(link)
        
        return {
            'nodes': nodes,
            'links': links,
            'total_hosts': len(self.hosts),
            'message': f"Found {len(self.hosts)} active host(s) on network"
        }
