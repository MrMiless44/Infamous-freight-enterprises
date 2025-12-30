import React, { useEffect, useState } from 'react';
import { useWebSocketContext } from '../contexts/WebSocketContext';
import type { Shipment } from '@infamous-freight/shared';

interface RealtimeShipmentListProps {
  initialShipments: Shipment[];
  onShipmentUpdate?: (shipment: Shipment) => void;
}

/**
 * Real-time Shipment List Component
 * Subscribes to WebSocket events for live shipment updates
 */
export function RealtimeShipmentList({
  initialShipments,
  onShipmentUpdate,
}: RealtimeShipmentListProps) {
  const { isConnected, subscribe, unsubscribe } = useWebSocketContext();
  const [shipments, setShipments] = useState<Shipment[]>(initialShipments);
  const [unreadUpdates, setUnreadUpdates] = useState(0);

  useEffect(() => {
    // Subscribe to shipment updates
    const handleShipmentUpdate = (data: {
      shipmentId: string;
      status: string;
      location?: { lat: number; lng: number };
      updatedAt: string;
    }) => {
      setShipments((prev) =>
        prev.map((s) =>
          s.id === data.shipmentId
            ? {
                ...s,
                status: data.status as any,
                location: data.location,
                updatedAt: new Date(data.updatedAt),
              }
            : s
        )
      );

      // Notify parent component
      const updated = shipments.find((s) => s.id === data.shipmentId);
      if (updated && onShipmentUpdate) {
        onShipmentUpdate({ ...updated, status: data.status as any });
      }

      // Increment unread counter
      setUnreadUpdates((prev) => prev + 1);
    };

    subscribe('shipment:update', handleShipmentUpdate);

    return () => {
      unsubscribe('shipment:update');
    };
  }, [subscribe, unsubscribe, onShipmentUpdate, shipments]);

  // Status color mapping
  const getStatusColor = (status: string): string => {
    const colors: Record<string, string> = {
      pending: 'bg-yellow-100 text-yellow-800',
      in_transit: 'bg-blue-100 text-blue-800',
      delivered: 'bg-green-100 text-green-800',
      cancelled: 'bg-red-100 text-red-800',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-4">
      {/* Connection Status */}
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Shipments (Live)</h2>
        <div className="flex items-center gap-2">
          <div
            className={`h-3 w-3 rounded-full ${
              isConnected ? 'bg-green-500' : 'bg-red-500'
            }`}
          />
          <span className="text-sm text-gray-600">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
          {unreadUpdates > 0 && (
            <span className="ml-2 inline-flex items-center rounded-full bg-red-100 px-3 py-1 text-xs font-medium text-red-800">
              {unreadUpdates} updates
            </span>
          )}
        </div>
      </div>

      {/* Shipments List */}
      <div className="grid gap-4">
        {shipments.map((shipment) => (
          <div
            key={shipment.id}
            className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm hover:shadow-md transition-shadow"
          >
            <div className="mb-3 flex items-start justify-between">
              <div>
                <h3 className="font-semibold text-gray-900">{shipment.id}</h3>
                <p className="text-sm text-gray-600">
                  {shipment.origin} → {shipment.destination}
                </p>
              </div>
              <span
                className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-medium ${getStatusColor(
                  shipment.status
                )}`}
              >
                {shipment.status}
              </span>
            </div>

            <div className="space-y-2 border-t border-gray-100 pt-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-600">Driver:</span>
                <span className="font-medium">
                  {(shipment as any).driver?.name || 'Unassigned'}
                </span>
              </div>

              {(shipment as any).location && (
                <div className="flex justify-between">
                  <span className="text-gray-600">Location:</span>
                  <span className="font-medium">
                    {(shipment as any).location.lat.toFixed(4)},
                    {(shipment as any).location.lng.toFixed(4)}
                  </span>
                </div>
              )}

              <div className="flex justify-between">
                <span className="text-gray-600">Updated:</span>
                <span className="font-medium">
                  {new Date(shipment.updatedAt).toLocaleString()}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Empty State */}
      {shipments.length === 0 && (
        <div className="rounded-lg border border-gray-200 bg-gray-50 p-8 text-center">
          <p className="text-gray-600">No shipments to display</p>
        </div>
      )}
    </div>
  );
}

export default RealtimeShipmentList;
