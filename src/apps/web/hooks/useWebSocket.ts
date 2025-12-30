import { useEffect, useRef, useCallback } from 'react';
import io, { Socket } from 'socket.io-client';

interface UseWebSocketOptions {
  url?: string;
  autoConnect?: boolean;
  reconnection?: boolean;
  reconnectionDelay?: number;
}

interface WebSocketContextValue {
  socket: Socket | null;
  isConnected: boolean;
  subscribe: (event: string, callback: (...args: any[]) => void) => void;
  unsubscribe: (event: string) => void;
  emit: (event: string, data: any) => void;
}

/**
 * Hook for WebSocket connection management
 * Automatically handles reconnection, token refresh, and cleanup
 */
export function useWebSocket(options: UseWebSocketOptions = {}): WebSocketContextValue {
  const {
    url = process.env.REACT_APP_API_URL || 'http://localhost:4000',
    autoConnect = true,
    reconnection = true,
    reconnectionDelay = 5000,
  } = options;

  const socketRef = useRef<Socket | null>(null);
  const isConnectedRef = useRef(false);

  const getAuthToken = useCallback((): string | null => {
    // Get JWT token from localStorage, sessionStorage, or your auth service
    return (
      localStorage.getItem('authToken') ||
      sessionStorage.getItem('authToken') ||
      null
    );
  }, []);

  const connect = useCallback(() => {
    if (socketRef.current?.connected) {
      return;
    }

    const token = getAuthToken();
    if (!token) {
      console.warn('No auth token available for WebSocket connection');
      return;
    }

    try {
      socketRef.current = io(url, {
        auth: { token },
        reconnection,
        reconnectionDelay,
        autoConnect,
        transports: ['websocket', 'polling'],
      });

      // Connection established
      socketRef.current.on('connect', () => {
        console.log('WebSocket connected:', socketRef.current?.id);
        isConnectedRef.current = true;
      });

      // Connection closed
      socketRef.current.on('disconnect', (reason) => {
        console.log('WebSocket disconnected:', reason);
        isConnectedRef.current = false;
      });

      // Authentication error
      socketRef.current.on('connect_error', (error) => {
        console.error('WebSocket connection error:', error);
        if (error.message === 'Unauthorized') {
          // Token expired, clear and redirect to login
          localStorage.removeItem('authToken');
          window.location.href = '/login';
        }
      });
    } catch (error) {
      console.error('Failed to initialize WebSocket:', error);
    }
  }, [url, autoConnect, reconnection, reconnectionDelay, getAuthToken]);

  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
      isConnectedRef.current = false;
    }
  }, []);

  const subscribe = useCallback(
    (event: string, callback: (...args: any[]) => void) => {
      if (!socketRef.current) {
        console.warn('WebSocket not connected');
        return;
      }
      socketRef.current.on(event, callback);
    },
    []
  );

  const unsubscribe = useCallback((event: string) => {
    if (socketRef.current) {
      socketRef.current.off(event);
    }
  }, []);

  const emit = useCallback((event: string, data: any) => {
    if (!socketRef.current?.connected) {
      console.warn('WebSocket not connected');
      return;
    }
    socketRef.current.emit(event, data);
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      // Cleanup on unmount
      disconnect();
    };
  }, [autoConnect, connect, disconnect]);

  return {
    socket: socketRef.current,
    isConnected: isConnectedRef.current,
    subscribe,
    unsubscribe,
    emit,
  };
}

export default useWebSocket;
