"""
Advanced scanning engine with next-generation async patterns
Implements AI-powered intelligence and military-grade evasion
Created by @lonefaisal - Made with ♥️ by @lonefaisal
"""

import asyncio
import aiohttp
import random
import time
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional, Set, Callable
from dataclasses import dataclass
import logging
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.live import Live
from rich.table import Table
from rich.panel import Panel

from .utils import create_semaphore, is_valid_hostname
from .output import OutputManager

console = Console()
logger = logging.getLogger(__name__)


@dataclass
class ScanMetrics:
    """Advanced scan metrics and statistics"""
    scan_id: str
    start_time: float
    targets_total: int = 0
    targets_completed: int = 0
    targets_successful: int = 0
    targets_failed: int = 0
    requests_per_second: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    false_positives: int = 0
    anomalies_detected: int = 0


class AsyncRateLimiter:
    """Advanced rate limiter with adaptive behavior"""
    
    def __init__(self, max_rate: float = 100.0, burst_size: int = 10):
        self.max_rate = max_rate
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens with rate limiting"""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst_size,
                self.tokens + elapsed * self.max_rate
            )
            self.last_update = now
            
            # Wait if not enough tokens
            if self.tokens < tokens:
                wait_time = (tokens - self.tokens) / self.max_rate
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= tokens
    
    async def adapt_rate(self, success_rate: float) -> None:
        """Adapt rate based on success rate"""
        if success_rate > 0.9:
            self.max_rate = min(self.max_rate * 1.1, 1000.0)
        elif success_rate < 0.5:
            self.max_rate = max(self.max_rate * 0.8, 10.0)


class CircuitBreaker:
    """Circuit breaker for fault tolerance"""
    
    def __init__(self, failure_threshold: int = 5, timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = 'closed'  # closed, open, half-open
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Call function through circuit breaker"""
        if self.state == 'open':
            if time.time() - self.last_failure_time > self.timeout:
                self.state = 'half-open'
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = await func(*args, **kwargs)
            if self.state == 'half-open':
                self.state = 'closed'
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'
            
            raise e


class StealthScanner:
    """Military-grade stealth scanning with advanced evasion"""
    
    def __init__(self):
        self.timing_profiles = {
            'paranoid': {'delay': (5, 15), 'jitter': 0.3, 'burst': 1},
            'sneaky': {'delay': (1, 3), 'jitter': 0.2, 'burst': 3},
            'polite': {'delay': (0.5, 1), 'jitter': 0.1, 'burst': 5},
            'aggressive': {'delay': (0, 0.1), 'jitter': 0, 'burst': 10}
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)',
            'Mozilla/5.0 (Android 11; Mobile; rv:92.0) Gecko/92.0'
        ]
    
    async def adaptive_delay(self, profile: str = 'polite') -> None:
        """Adaptive delay with jitter"""
        config = self.timing_profiles.get(profile, self.timing_profiles['polite'])
        base_delay = random.uniform(*config['delay'])
        jitter = random.uniform(-config['jitter'], config['jitter'])
        delay = max(0, base_delay + jitter)
        
        if delay > 0:
            await asyncio.sleep(delay)
    
    def get_random_user_agent(self) -> str:
        """Get random user agent for stealth"""
        return random.choice(self.user_agents)
    
    def generate_decoy_headers(self) -> Dict[str, str]:
        """Generate decoy headers to mimic real traffic"""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }


class AIIntelligenceEngine:
    """AI-powered intelligence for smart scanning"""
    
    def __init__(self):
        self.pattern_cache = {}
        self.anomaly_threshold = 0.7
        self.learning_data = []
    
    async def calculate_target_score(self, target: str) -> float:
        """Calculate target priority score using AI"""
        score = 0.5  # Base score
        
        # Domain characteristics
        if '.' in target:
            parts = target.split('.')
            
            # TLD scoring
            tld = parts[-1].lower()
            tld_scores = {
                'com': 0.9, 'net': 0.8, 'org': 0.7, 'edu': 0.6,
                'gov': 0.95, 'mil': 0.98, 'io': 0.75
            }
            score *= tld_scores.get(tld, 0.5)
            
            # Subdomain depth scoring
            if len(parts) > 2:
                subdomain_score = min(1.0, 0.8 + (len(parts) - 2) * 0.1)
                score *= subdomain_score
            
            # Common service patterns
            service_patterns = {
                'api': 0.9, 'admin': 0.95, 'panel': 0.9, 'dashboard': 0.85,
                'staging': 0.8, 'dev': 0.75, 'test': 0.7, 'mail': 0.8
            }
            
            for part in parts[:-2]:  # Exclude domain and TLD
                for pattern, pattern_score in service_patterns.items():
                    if pattern in part.lower():
                        score *= pattern_score
                        break
        
        return min(1.0, score)
    
    async def detect_anomaly(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalous responses using pattern analysis"""
        anomaly_indicators = []
        score = 0.0
        
        # Response time anomaly
        response_time = response_data.get('response_time', 0)
        if response_time > 10000:  # > 10 seconds
            anomaly_indicators.append('slow_response')
            score += 0.3
        
        # Status code anomaly
        status_code = response_data.get('status_code', 200)
        if status_code in [418, 429, 503, 999]:  # Unusual status codes
            anomaly_indicators.append('unusual_status')
            score += 0.4
        
        # Content length anomaly
        content_length = response_data.get('content_length', 0)
        if content_length == 0 or content_length > 1000000:  # Empty or very large
            anomaly_indicators.append('unusual_content_size')
            score += 0.2
        
        # Header anomaly detection
        headers = response_data.get('headers', {})
        suspicious_headers = ['x-real-ip', 'x-forwarded-for', 'x-debug']
        if any(header.lower() in headers for header in suspicious_headers):
            anomaly_indicators.append('suspicious_headers')
            score += 0.3
        
        return {
            'is_anomalous': score > self.anomaly_threshold,
            'confidence': min(1.0, score),
            'indicators': anomaly_indicators,
            'score': score
        }
    
    async def learn_from_results(self, results: List[Dict[str, Any]]) -> None:
        """Learn from scan results to improve future performance"""
        self.learning_data.extend(results)
        
        # Analyze patterns in successful vs failed requests
        successful = [r for r in results if r.get('success', False)]
        failed = [r for r in results if not r.get('success', False)]
        
        # Update anomaly threshold based on results
        if len(self.learning_data) > 100:
            # Calculate new threshold based on historical data
            anomaly_scores = [r.get('anomaly_score', 0) for r in self.learning_data[-100:]]
            if anomaly_scores:
                self.anomaly_threshold = sum(anomaly_scores) / len(anomaly_scores) + 0.2


class NextGenAsyncEngine:
    """Next-generation async scanning engine with advanced capabilities"""
    
    def __init__(
        self,
        max_concurrent: int = 1000,
        stealth_profile: str = 'polite',
        ai_enabled: bool = True
    ):
        self.max_concurrent = max_concurrent
        self.stealth_profile = stealth_profile
        self.ai_enabled = ai_enabled
        
        # Initialize components
        self.rate_limiter = AsyncRateLimiter(max_rate=max_concurrent/10)
        self.circuit_breaker = CircuitBreaker()
        self.stealth_scanner = StealthScanner()
        self.ai_engine = AIIntelligenceEngine() if ai_enabled else None
        self.output_manager = OutputManager()
        
        # Metrics tracking
        self.metrics = None
        self.observers: List[Callable] = []
    
    def attach_observer(self, observer: Callable) -> None:
        """Attach observer for real-time updates"""
        self.observers.append(observer)
    
    async def notify_observers(self, event_type: str, data: Dict[str, Any]) -> None:
        """Notify all observers of events"""
        for observer in self.observers:
            try:
                await observer(event_type, data)
            except Exception as e:
                logger.error(f"Observer notification failed: {e}")
    
    async def create_optimized_session(self) -> aiohttp.ClientSession:
        """Create optimized aiohttp session"""
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent * 2,
            limit_per_host=min(self.max_concurrent, 100),
            ttl_dns_cache=300,
            use_dns_cache=True,
            enable_cleanup_closed=True,
            force_close=False,
            keepalive_timeout=30
        )
        
        timeout = aiohttp.ClientTimeout(
            total=60,
            connect=15,
            sock_read=30
        )
        
        headers = {
            'User-Agent': self.stealth_scanner.get_random_user_agent(),
            **self.stealth_scanner.generate_decoy_headers()
        }
        
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers
        )
    
    async def intelligent_scan_task(
        self,
        semaphore: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        target: str
    ) -> Dict[str, Any]:
        """Intelligent scanning task with advanced features"""
        async with semaphore:
            start_time = time.time()
            
            try:
                # Rate limiting
                await self.rate_limiter.acquire()
                
                # Stealth delay
                await self.stealth_scanner.adaptive_delay(self.stealth_profile)
                
                # Perform scan through circuit breaker
                result = await self.circuit_breaker.call(
                    self._execute_scan, session, target
                )
                
                # AI analysis if enabled
                if self.ai_enabled and self.ai_engine:
                    anomaly_info = await self.ai_engine.detect_anomaly(result)
                    result['anomaly'] = anomaly_info
                    
                    if anomaly_info['is_anomalous']:
                        self.metrics.anomalies_detected += 1
                
                # Update metrics
                self.metrics.targets_completed += 1
                if result.get('success', False):
                    self.metrics.targets_successful += 1
                else:
                    self.metrics.targets_failed += 1
                
                # Calculate current RPS
                elapsed = time.time() - self.metrics.start_time
                if elapsed > 0:
                    self.metrics.requests_per_second = self.metrics.targets_completed / elapsed
                
                # Notify observers
                await self.notify_observers('scan_progress', {
                    'target': target,
                    'result': result,
                    'metrics': self.metrics
                })
                
                return result
                
            except Exception as e:
                error_result = {
                    'target': target,
                    'success': False,
                    'error': str(e),
                    'response_time': (time.time() - start_time) * 1000,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                self.metrics.targets_completed += 1
                self.metrics.targets_failed += 1
                
                return error_result
    
    async def _execute_scan(
        self,
        session: aiohttp.ClientSession,
        target: str
    ) -> Dict[str, Any]:
        """Execute actual scan operation"""
        start_time = time.time()
        
        try:
            # Try HTTPS first, then HTTP
            for scheme in ['https', 'http']:
                url = f"{scheme}://{target}"
                
                try:
                    async with session.get(url, ssl=False) as response:
                        content = await response.read()
                        
                        result = {
                            'target': target,
                            'url': url,
                            'success': True,
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'content_length': len(content),
                            'response_time': (time.time() - start_time) * 1000,
                            'scheme': scheme,
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        
                        return result
                        
                except aiohttp.ClientError:
                    continue
            
            # If both schemes failed
            return {
                'target': target,
                'success': False,
                'error': 'Connection failed for both HTTP and HTTPS',
                'response_time': (time.time() - start_time) * 1000,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'target': target,
                'success': False,
                'error': str(e),
                'response_time': (time.time() - start_time) * 1000,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    async def scan_with_intelligence(
        self,
        targets: List[str],
        progress_callback: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """Intelligent scanning with AI prioritization"""
        # Initialize metrics
        self.metrics = ScanMetrics(
            scan_id=uuid.uuid4().hex,
            start_time=time.time(),
            targets_total=len(targets)
        )
        
        # AI-powered target prioritization
        if self.ai_enabled and self.ai_engine:
            if not console.is_quiet:
                console.print("[blue]🧠 AI analyzing and prioritizing targets...[/blue]")
            
            prioritized_targets = []
            for target in targets:
                if is_valid_hostname(target):
                    score = await self.ai_engine.calculate_target_score(target)
                    prioritized_targets.append((target, score))
            
            # Sort by priority score (highest first)
            prioritized_targets.sort(key=lambda x: x[1], reverse=True)
            sorted_targets = [target for target, score in prioritized_targets]
        else:
            sorted_targets = [t for t in targets if is_valid_hostname(t)]
        
        if not console.is_quiet:
            console.print(f"[green]🎯 Scanning {len(sorted_targets)} targets with advanced engine[/green]")
        
        # Create optimized session
        async with await self.create_optimized_session() as session:
            semaphore = asyncio.Semaphore(self.max_concurrent)
            
            # Create scanning tasks
            tasks = [
                self.intelligent_scan_task(semaphore, session, target)
                for target in sorted_targets
            ]
            
            # Execute with progress tracking
            results = []
            
            if progress_callback:
                # Custom progress callback
                for coro in asyncio.as_completed(tasks):
                    result = await coro
                    results.append(result)
                    await progress_callback(len(results), len(tasks), result)
            
            elif not console.is_quiet:
                # Rich progress display
                with Progress(
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("({task.completed}/{task.total})"),
                    TextColumn("• [green]{task.fields[rps]:.1f} req/s[/green]"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task(
                        "🚀 Advanced scanning",
                        total=len(tasks),
                        rps=0.0
                    )
                    
                    for coro in asyncio.as_completed(tasks):
                        result = await coro
                        results.append(result)
                        
                        # Update progress with RPS
                        progress.update(
                            task,
                            advance=1,
                            rps=self.metrics.requests_per_second
                        )
            else:
                # Silent mode - just gather results
                results = await asyncio.gather(*tasks, return_exceptions=True)
                results = [r for r in results if isinstance(r, dict)]
        
        # Post-processing and learning
        if self.ai_enabled and self.ai_engine:
            await self.ai_engine.learn_from_results(results)
        
        # Final metrics
        total_time = time.time() - self.metrics.start_time
        if not console.is_quiet:
            self._display_final_metrics(results, total_time)
        
        return results
    
    def _display_final_metrics(self, results: List[Dict[str, Any]], total_time: float) -> None:
        """Display final scan metrics"""
        successful = len([r for r in results if r.get('success', False)])
        failed = len(results) - successful
        anomalies = len([r for r in results if r.get('anomaly', {}).get('is_anomalous', False)])
        
        # Create metrics table
        table = Table(title="🏆 Advanced Scan Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Targets", str(len(results)))
        table.add_row("Successful", f"{successful} ({successful/len(results)*100:.1f}%)")
        table.add_row("Failed", f"{failed} ({failed/len(results)*100:.1f}%)")
        table.add_row("Anomalies Detected", str(anomalies))
        table.add_row("Average RPS", f"{len(results)/total_time:.2f}")
        table.add_row("Total Time", f"{total_time:.2f}s")
        table.add_row("Scan ID", self.metrics.scan_id[:12] + "...")
        
        console.print(Panel(table, title="📊 Scan Complete", border_style="green"))


if __name__ == "__main__":
    # Test the advanced engine
    import sys
    
    async def test_advanced_engine():
        if len(sys.argv) < 2:
            print("Usage: python advanced_engine.py <target1> [target2] ...")
            sys.exit(1)
        
        targets = sys.argv[1:]
        
        # Create advanced engine
        engine = NextGenAsyncEngine(
            max_concurrent=100,
            stealth_profile='polite',
            ai_enabled=True
        )
        
        print(f"🚀 Testing advanced engine with {len(targets)} targets")
        
        # Run scan
        results = await engine.scan_with_intelligence(targets)
        
        print(f"\n✅ Scan complete: {len(results)} results")
        for result in results[:5]:  # Show first 5
            target = result.get('target')
            success = result.get('success', False)
            status = "SUCCESS" if success else "FAILED"
            print(f"  {target}: {status}")
    
    asyncio.run(test_advanced_engine())