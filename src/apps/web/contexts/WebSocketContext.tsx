import React, { createContext, useContext, ReactNode } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Socket } from 'socket.io-client';

interface WebSocketContextType {
  socket: Socket | null;
  isConnected: boolean;
  subscribe: (event: string, callback: (...args: any[]) => void) => void;
  unsubscribe: (event: string) => void;
  emit: (event: string, data: any) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(
  undefined
);

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const webSocket = useWebSocket({
    autoConnect: true,
    reconnection: true,
  });

  return (
    <WebSocketContext.Provider value={webSocket}>
      {children}
    </WebSocketContext.Provider>
  );
}

export function useWebSocketContext() {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocketContext must be used within WebSocketProvider');
  }
  return context;
}

export default WebSocketContext;
