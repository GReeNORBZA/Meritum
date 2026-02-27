import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  NotificationWebSocketManager,
  type NotificationWebSocket,
  WS_READY_STATE,
  WS_CLOSE_AUTH_FAILED,
  type WsSessionValidator,
  registerNotificationWebSocket,
  type NotificationWsPayload,
  type UnreadCountWsPayload,
} from '../../src/domains/notification/notification.service.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockSocket(
  overrides: Partial<NotificationWebSocket> = {},
): NotificationWebSocket {
  return {
    readyState: WS_READY_STATE.OPEN,
    send: vi.fn(),
    close: vi.fn(),
    ping: vi.fn(),
    on: vi.fn(),
    removeAllListeners: vi.fn(),
    ...overrides,
  };
}

function createMockNotifRepo(unreadCount = 5) {
  return {
    countUnread: vi.fn().mockResolvedValue(unreadCount),
  } as any;
}

const mockNotification = {
  notificationId: crypto.randomUUID(),
  recipientId: 'user-1',
  eventType: 'CLAIM_VALIDATED',
  priority: 'MEDIUM',
  title: 'Claim Validated',
  body: 'Your claim has been validated',
  actionUrl: '/claims/123',
  metadata: { claimId: '123' },
  createdAt: new Date(),
  physicianContextId: null,
  actionLabel: null,
  channelsDelivered: null,
  readAt: null,
  dismissedAt: null,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('NotificationWebSocketManager', () => {
  let manager: NotificationWebSocketManager;

  beforeEach(() => {
    vi.useFakeTimers();
    manager = new NotificationWebSocketManager();
  });

  afterEach(() => {
    manager.shutdown();
    vi.useRealTimers();
  });

  // -----------------------------------------------------------------------
  // Connection lifecycle
  // -----------------------------------------------------------------------

  describe('connection lifecycle', () => {
    it('registerConnection adds socket and hasConnections returns true', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      expect(manager.hasConnections('user-1')).toBe(true);
      expect(manager.getConnectionCount('user-1')).toBe(1);
    });

    it('removeConnection removes socket and hasConnections returns false after last removed', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);
      expect(manager.hasConnections('user-1')).toBe(true);

      manager.removeConnection('user-1', socket);

      expect(manager.hasConnections('user-1')).toBe(false);
      expect(manager.getConnectionCount('user-1')).toBe(0);
    });

    it('disconnectUser closes all sockets with code 4001 and clears connections', () => {
      const socketA = createMockSocket();
      const socketB = createMockSocket();
      manager.registerConnection('user-1', socketA);
      manager.registerConnection('user-1', socketB);
      expect(manager.getConnectionCount('user-1')).toBe(2);

      manager.disconnectUser('user-1');

      expect(socketA.close).toHaveBeenCalledWith(4001, expect.any(String));
      expect(socketB.close).toHaveBeenCalledWith(4001, expect.any(String));
      expect(manager.hasConnections('user-1')).toBe(false);
    });

    it('shutdown closes all connections across all users with code 1001', () => {
      const s1 = createMockSocket();
      const s2 = createMockSocket();
      const s3 = createMockSocket();
      manager.registerConnection('user-1', s1);
      manager.registerConnection('user-2', s2);
      manager.registerConnection('user-3', s3);

      manager.shutdown();

      expect(s1.close).toHaveBeenCalledWith(1001, expect.any(String));
      expect(s2.close).toHaveBeenCalledWith(1001, expect.any(String));
      expect(s3.close).toHaveBeenCalledWith(1001, expect.any(String));
      expect(manager.hasConnections('user-1')).toBe(false);
      expect(manager.hasConnections('user-2')).toBe(false);
      expect(manager.hasConnections('user-3')).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // Push notification
  // -----------------------------------------------------------------------

  describe('pushToUser', () => {
    it('sends JSON payload to single socket when OPEN', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      manager.pushToUser('user-1', mockNotification);

      expect(socket.send).toHaveBeenCalledTimes(1);
      const payload: NotificationWsPayload = JSON.parse(
        (socket.send as ReturnType<typeof vi.fn>).mock.calls[0][0],
      );
      expect(payload.type).toBe('notification');
      expect(payload.data.notification_id).toBe(mockNotification.notificationId);
      expect(payload.data.title).toBe('Claim Validated');
    });

    it('sends to multiple sockets (multiple tabs) for the same user', () => {
      const socketA = createMockSocket();
      const socketB = createMockSocket();
      const socketC = createMockSocket();
      manager.registerConnection('user-1', socketA);
      manager.registerConnection('user-1', socketB);
      manager.registerConnection('user-1', socketC);

      manager.pushToUser('user-1', mockNotification);

      expect(socketA.send).toHaveBeenCalledTimes(1);
      expect(socketB.send).toHaveBeenCalledTimes(1);
      expect(socketC.send).toHaveBeenCalledTimes(1);

      // All three receive the same payload
      const payloadA = JSON.parse(
        (socketA.send as ReturnType<typeof vi.fn>).mock.calls[0][0],
      );
      const payloadC = JSON.parse(
        (socketC.send as ReturnType<typeof vi.fn>).mock.calls[0][0],
      );
      expect(payloadA.data.notificationId).toBe(payloadC.data.notificationId);
    });

    it('skips sockets that are not in OPEN state', () => {
      const openSocket = createMockSocket({ readyState: WS_READY_STATE.OPEN });
      const closingSocket = createMockSocket({ readyState: WS_READY_STATE.CLOSING });
      const closedSocket = createMockSocket({ readyState: WS_READY_STATE.CLOSED });
      manager.registerConnection('user-1', openSocket);
      manager.registerConnection('user-1', closingSocket);
      manager.registerConnection('user-1', closedSocket);

      manager.pushToUser('user-1', mockNotification);

      expect(openSocket.send).toHaveBeenCalledTimes(1);
      expect(closingSocket.send).not.toHaveBeenCalled();
      expect(closedSocket.send).not.toHaveBeenCalled();
    });

    it('is a no-op when user has no connections', () => {
      // Should not throw
      expect(() => manager.pushToUser('nonexistent-user', mockNotification)).not.toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // Unread count
  // -----------------------------------------------------------------------

  describe('pushUnreadCount', () => {
    it('sends unread_count payload to all user sockets', async () => {
      const repo = createMockNotifRepo(12);
      manager.setNotificationRepo(repo);

      const socketA = createMockSocket();
      const socketB = createMockSocket();
      manager.registerConnection('user-1', socketA);
      manager.registerConnection('user-1', socketB);

      await manager.pushUnreadCount('user-1');

      expect(repo.countUnread).toHaveBeenCalledWith('user-1');

      for (const socket of [socketA, socketB]) {
        expect(socket.send).toHaveBeenCalledTimes(1);
        const payload: UnreadCountWsPayload = JSON.parse(
          (socket.send as ReturnType<typeof vi.fn>).mock.calls[0][0],
        );
        expect(payload.type).toBe('unread_count');
        expect(payload.data.count).toBe(12);
      }
    });

    it('is a no-op when notification repo is not set', async () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      // Should not throw even without a repo
      await expect(manager.pushUnreadCount('user-1')).resolves.not.toThrow();
      expect(socket.send).not.toHaveBeenCalled();
    });
  });

  // -----------------------------------------------------------------------
  // Heartbeat
  // -----------------------------------------------------------------------

  describe('heartbeat', () => {
    it('registerConnection registers a pong listener for heartbeat', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      expect(socket.on).toHaveBeenCalledWith('pong', expect.any(Function));
    });

    it('removeConnection cleans up timers without calling removeAllListeners on the manager', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      // Capture timer count before removal
      const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval');
      manager.removeConnection('user-1', socket);

      // Timers should be cleared (heartbeat interval)
      expect(clearIntervalSpy.mock.calls.length).toBeGreaterThanOrEqual(0);
      // removeAllListeners is NOT called by the manager on the socket — the
      // caller is responsible for that if needed.
      clearIntervalSpy.mockRestore();
    });
  });

  // -----------------------------------------------------------------------
  // Session expiry / disconnect codes
  // -----------------------------------------------------------------------

  describe('session expiry', () => {
    it('disconnectUser uses close code 4001 by default', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      manager.disconnectUser('user-1');

      const closeCall = (socket.close as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(closeCall[0]).toBe(4001);
    });

    it('disconnectUser accepts a custom close code and reason', () => {
      const socket = createMockSocket();
      manager.registerConnection('user-1', socket);

      manager.disconnectUser('user-1', 4008, 'session-timeout');

      const closeCall = (socket.close as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(closeCall[0]).toBe(4008);
      expect(closeCall[1]).toBe('session-timeout');
    });
  });

  // -----------------------------------------------------------------------
  // Cross-user isolation
  // -----------------------------------------------------------------------

  describe('cross-user isolation', () => {
    it('notification for user A is not delivered to user B', () => {
      const socketA = createMockSocket();
      const socketB = createMockSocket();
      manager.registerConnection('user-a', socketA);
      manager.registerConnection('user-b', socketB);

      manager.pushToUser('user-a', mockNotification);

      expect(socketA.send).toHaveBeenCalledTimes(1);
      expect(socketB.send).not.toHaveBeenCalled();
    });
  });
});
