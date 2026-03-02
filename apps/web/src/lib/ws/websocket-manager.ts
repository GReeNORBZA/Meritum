type MessageHandler = (data: unknown) => void;

interface WebSocketMessage {
  type: string;
  payload: unknown;
}

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:3001';
const HEARTBEAT_INTERVAL = 30000;
const MAX_RECONNECT_DELAY = 30000;

class WebSocketManager {
  private ws: WebSocket | null = null;
  private handlers = new Map<string, Set<MessageHandler>>();
  private reconnectAttempt = 0;
  private reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private isLeader = false;
  private bc: BroadcastChannel | null = null;

  connect() {
    if (typeof window === 'undefined') return;

    // Leader election via BroadcastChannel
    try {
      this.bc = new BroadcastChannel('meritum-ws');
      this.bc.onmessage = (event) => {
        if (event.data.type === 'ws-message') {
          this.dispatchMessage(event.data.message);
        }
      };
    } catch {
      // BroadcastChannel not supported, this tab is always leader
    }

    this.isLeader = true;
    this.doConnect();
  }

  private doConnect() {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(`${WS_BASE}/ws`);
    } catch {
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.startHeartbeat();
    };

    this.ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data);

        if (message.type === 'pong') return;

        this.dispatchMessage(message);

        // Broadcast to other tabs
        this.bc?.postMessage({ type: 'ws-message', message });
      } catch {
        // Ignore malformed
      }
    };

    this.ws.onclose = () => {
      this.stopHeartbeat();
      this.scheduleReconnect();
    };

    this.ws.onerror = () => {
      this.ws?.close();
    };
  }

  private dispatchMessage(message: WebSocketMessage) {
    const typeHandlers = this.handlers.get(message.type);
    if (typeHandlers) {
      typeHandlers.forEach((handler) => handler(message.payload));
    }

    const allHandlers = this.handlers.get('*');
    if (allHandlers) {
      allHandlers.forEach((handler) => handler(message));
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) return;

    const delay = Math.min(
      1000 * Math.pow(2, this.reconnectAttempt),
      MAX_RECONNECT_DELAY
    );
    this.reconnectAttempt++;
    this.reconnectTimeout = setTimeout(() => {
      this.reconnectTimeout = null;
      if (this.isLeader) {
        this.doConnect();
      }
    }, delay);
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, HEARTBEAT_INTERVAL);
  }

  private stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  subscribe(type: string, handler: MessageHandler): () => void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler);

    return () => {
      this.handlers.get(type)?.delete(handler);
      if (this.handlers.get(type)?.size === 0) {
        this.handlers.delete(type);
      }
    };
  }

  send(type: string, payload: unknown) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({ type, payload }));
    }
  }

  disconnect() {
    this.stopHeartbeat();
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
    this.ws?.close();
    this.ws = null;
    this.bc?.close();
    this.bc = null;
  }
}

export const wsManager = new WebSocketManager();
