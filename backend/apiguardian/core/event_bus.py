"""Event Bus - Pub/Sub system with Redis fallback to in-process"""
import asyncio
import json
import logging
import os
from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import uuid

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Event data structure"""
    id: str
    type: str
    data: Dict[str, Any]
    timestamp: str
    source: str = "apiguardian"
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Event':
        return cls(**data)
    
    @classmethod
    def create(cls, event_type: str, data: Dict, source: str = "apiguardian") -> 'Event':
        return cls(
            id=str(uuid.uuid4()),
            type=event_type,
            data=data,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=source
        )


class InProcessEventBus:
    """In-process event bus using asyncio queues"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._queues: Dict[str, asyncio.Queue] = {}
        self._running = False
        self._tasks: List[asyncio.Task] = []
        
    async def start(self):
        """Start the event bus"""
        self._running = True
        logger.info("In-process event bus started")
        
    async def stop(self):
        """Stop the event bus"""
        self._running = False
        for task in self._tasks:
            task.cancel()
        logger.info("In-process event bus stopped")
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event type"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
        logger.debug(f"Subscribed to {event_type}")
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """Unsubscribe from an event type"""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [
                cb for cb in self._subscribers[event_type] if cb != callback
            ]
    
    async def publish(self, event: Event):
        """Publish an event to all subscribers"""
        event_type = event.type
        
        # Notify direct subscribers
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_type}: {e}")
        
        # Also notify wildcard subscribers
        if '*' in self._subscribers:
            for callback in self._subscribers['*']:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                except Exception as e:
                    logger.error(f"Error in wildcard event handler: {e}")
        
        logger.debug(f"Published event: {event_type}")
    
    def get_queue(self, name: str) -> asyncio.Queue:
        """Get or create a named queue"""
        if name not in self._queues:
            self._queues[name] = asyncio.Queue()
        return self._queues[name]


class RedisEventBus:
    """Redis-backed event bus using pub/sub"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._redis = None
        self._pubsub = None
        self._subscribers: Dict[str, List[Callable]] = {}
        self._running = False
        self._task = None
        
    async def start(self):
        """Start the Redis event bus"""
        try:
            import redis.asyncio as redis
            self._redis = redis.from_url(self.redis_url)
            self._pubsub = self._redis.pubsub()
            self._running = True
            self._task = asyncio.create_task(self._listen())
            logger.info("Redis event bus started")
        except ImportError:
            logger.error("redis package not installed, falling back to in-process")
            raise
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def stop(self):
        """Stop the Redis event bus"""
        self._running = False
        if self._task:
            self._task.cancel()
        if self._pubsub:
            await self._pubsub.close()
        if self._redis:
            await self._redis.close()
        logger.info("Redis event bus stopped")
    
    async def _listen(self):
        """Listen for messages"""
        while self._running:
            try:
                message = await self._pubsub.get_message(ignore_subscribe_messages=True)
                if message:
                    channel = message['channel'].decode()
                    data = json.loads(message['data'].decode())
                    event = Event.from_dict(data)
                    await self._dispatch(event)
            except Exception as e:
                logger.error(f"Error in Redis listener: {e}")
                await asyncio.sleep(1)
    
    async def _dispatch(self, event: Event):
        """Dispatch event to subscribers"""
        if event.type in self._subscribers:
            for callback in self._subscribers[event.type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(event)
                    else:
                        callback(event)
                except Exception as e:
                    logger.error(f"Error in event handler: {e}")
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event type"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
            asyncio.create_task(self._pubsub.subscribe(f"apiguardian:{event_type}"))
        self._subscribers[event_type].append(callback)
    
    async def publish(self, event: Event):
        """Publish an event"""
        channel = f"apiguardian:{event.type}"
        await self._redis.publish(channel, event.to_json())
        logger.debug(f"Published event to Redis: {event.type}")


class EventBus:
    """Event bus factory - uses Redis if available, falls back to in-process"""
    
    _instance: Optional['EventBus'] = None
    
    def __init__(self):
        self._backend = None
        self._websocket_clients: List[Any] = []
        
    @classmethod
    def get_instance(cls) -> 'EventBus':
        """Get singleton instance"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    async def initialize(self):
        """Initialize the event bus backend"""
        redis_url = os.environ.get('REDIS_URL')
        
        if redis_url:
            try:
                self._backend = RedisEventBus(redis_url)
                await self._backend.start()
                logger.info("Using Redis event bus")
                return
            except Exception as e:
                logger.warning(f"Redis not available, falling back to in-process: {e}")
        
        self._backend = InProcessEventBus()
        await self._backend.start()
        logger.info("Using in-process event bus")
    
    async def shutdown(self):
        """Shutdown the event bus"""
        if self._backend:
            await self._backend.stop()
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event type"""
        if self._backend:
            self._backend.subscribe(event_type, callback)
    
    async def publish(self, event: Event):
        """Publish an event"""
        if self._backend:
            await self._backend.publish(event)
        
        # Broadcast to WebSocket clients
        await self._broadcast_to_websockets(event)
    
    def register_websocket(self, websocket):
        """Register a WebSocket client for live updates"""
        self._websocket_clients.append(websocket)
    
    def unregister_websocket(self, websocket):
        """Unregister a WebSocket client"""
        if websocket in self._websocket_clients:
            self._websocket_clients.remove(websocket)
    
    async def _broadcast_to_websockets(self, event: Event):
        """Broadcast event to all connected WebSocket clients"""
        if not self._websocket_clients:
            return
        
        message = event.to_json()
        disconnected = []
        
        for ws in self._websocket_clients:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        
        # Clean up disconnected clients
        for ws in disconnected:
            self.unregister_websocket(ws)


# Global event bus instance
event_bus = EventBus.get_instance()
