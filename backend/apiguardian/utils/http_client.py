"""HTTP Client utilities with retry, timeout, and logging"""
import asyncio
import logging
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import httpx

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Standardized HTTP response"""
    status_code: int
    headers: Dict[str, str]
    body: str
    json_body: Optional[Dict] = None
    elapsed_ms: float = 0
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600


class HTTPClient:
    """Async HTTP client with retry and rate limiting"""
    
    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        rate_limit: float = 0.1,  # Min seconds between requests
        user_agent: str = "APIGuardian/1.0"
    ):
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self._last_request_time = 0
        self._client: Optional[httpx.AsyncClient] = None
        
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                headers={'User-Agent': self.user_agent}
            )
        return self._client
    
    async def close(self):
        """Close the HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def _rate_limit_wait(self):
        """Wait for rate limit"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        params: Dict[str, str] = None,
        data: Any = None,
        json: Dict = None,
        allow_redirects: bool = True,
        timeout: float = None
    ) -> HTTPResponse:
        """Make an HTTP request with retry logic"""
        # Use provided timeout or fall back to instance default
        request_timeout = timeout if timeout is not None else self.timeout

        # Use shared client for connection pooling
        client = await self._get_client()

        for attempt in range(self.max_retries + 1):
            await self._rate_limit_wait()

            try:
                start_time = time.time()

                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                    follow_redirects=allow_redirects,
                    timeout=httpx.Timeout(request_timeout)
                )

                elapsed_ms = (time.time() - start_time) * 1000

                # Try to parse JSON
                json_body = None
                try:
                    json_body = response.json()
                except Exception:
                    pass

                return HTTPResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text,
                    json_body=json_body,
                    elapsed_ms=elapsed_ms
                )

            except httpx.TimeoutException as e:
                logger.warning(f"Request timeout ({attempt + 1}/{self.max_retries + 1}): {url}")
                if attempt == self.max_retries:
                    return HTTPResponse(
                        status_code=0,
                        headers={},
                        body="",
                        error=f"Timeout: {str(e)}"
                    )
                await asyncio.sleep(self.retry_delay * (attempt + 1))

            except httpx.RequestError as e:
                logger.warning(f"Request error ({attempt + 1}/{self.max_retries + 1}): {url} - {e}")
                if attempt == self.max_retries:
                    return HTTPResponse(
                        status_code=0,
                        headers={},
                        body="",
                        error=f"Request error: {str(e)}"
                    )
                await asyncio.sleep(self.retry_delay * (attempt + 1))

        # Fallback return in case loop completes without returning
        return HTTPResponse(
            status_code=0,
            headers={},
            body="",
            error="All retry attempts exhausted"
        )
    
    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP GET request"""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP POST request"""
        return await self.request('POST', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP PUT request"""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP DELETE request"""
        return await self.request('DELETE', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP HEAD request"""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> HTTPResponse:
        """HTTP OPTIONS request"""
        return await self.request('OPTIONS', url, **kwargs)


class SafeHTTPClient(HTTPClient):
    """HTTP client that only allows safe (non-destructive) methods by default"""
    
    def __init__(self, allow_destructive: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.allow_destructive = allow_destructive
        self.safe_methods = {'GET', 'HEAD', 'OPTIONS'}
    
    async def request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """Make request with safety check"""
        if method.upper() not in self.safe_methods and not self.allow_destructive:
            logger.warning(f"Blocked destructive method {method} to {url}")
            return HTTPResponse(
                status_code=0,
                headers={},
                body="",
                error=f"Destructive method {method} blocked. Enable with allow_destructive=True"
            )
        return await super().request(method, url, **kwargs)


# Global HTTP client instance
http_client = HTTPClient()
safe_http_client = SafeHTTPClient()
