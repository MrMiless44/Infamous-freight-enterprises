/**
 * Mobile Offline Support
 * Caches data locally and syncs when connection restored
 */

import AsyncStorage from "@react-native-async-storage/async-storage";
import NetInfo from "@react-native-community/netinfo";

interface OfflineAction {
  id: string;
  type: string;
  data: any;
  timestamp: number;
}

const OFFLINE_QUEUE_KEY = "@infamous_freight:offline_queue";
const CACHED_DATA_KEY = "@infamous_freight:cached_data";

/**
 * Check if device is online
 */
export async function isOnline(): Promise<boolean> {
  const state = await NetInfo.fetch();
  return state.isConnected === true && state.isInternetReachable === true;
}

/**
 * Cache data for offline access
 */
export async function cacheData(key: string, data: any): Promise<void> {
  try {
    const cachedData = await AsyncStorage.getItem(CACHED_DATA_KEY);
    const cache = cachedData ? JSON.parse(cachedData) : {};

    cache[key] = {
      data,
      timestamp: Date.now(),
    };

    await AsyncStorage.setItem(CACHED_DATA_KEY, JSON.stringify(cache));
  } catch (error) {
    console.error("Failed to cache data:", error);
  }
}

/**
 * Get cached data
 */
export async function getCachedData(
  key: string,
  maxAge: number = 3600000,
): Promise<any | null> {
  try {
    const cachedData = await AsyncStorage.getItem(CACHED_DATA_KEY);
    if (!cachedData) return null;

    const cache = JSON.parse(cachedData);
    const item = cache[key];

    if (!item) return null;

    // Check if cache is expired
    if (Date.now() - item.timestamp > maxAge) {
      return null;
    }

    return item.data;
  } catch (error) {
    console.error("Failed to get cached data:", error);
    return null;
  }
}

/**
 * Queue action for when online
 */
export async function queueAction(type: string, data: any): Promise<void> {
  try {
    const queueData = await AsyncStorage.getItem(OFFLINE_QUEUE_KEY);
    const queue: OfflineAction[] = queueData ? JSON.parse(queueData) : [];

    queue.push({
      id: `${Date.now()}-${Math.random()}`,
      type,
      data,
      timestamp: Date.now(),
    });

    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(queue));
    console.log(`⏰ Queued action: ${type}`);
  } catch (error) {
    console.error("Failed to queue action:", error);
  }
}

/**
 * Sync queued actions when online
 */
export async function syncQueue(apiClient: any): Promise<void> {
  const online = await isOnline();
  if (!online) {
    console.log("📴 Device offline, skipping sync");
    return;
  }

  try {
    const queueData = await AsyncStorage.getItem(OFFLINE_QUEUE_KEY);
    if (!queueData) return;

    const queue: OfflineAction[] = JSON.parse(queueData);
    if (queue.length === 0) return;

    console.log(`🔄 Syncing ${queue.length} offline actions...`);

    const failed: OfflineAction[] = [];

    for (const action of queue) {
      try {
        await processAction(action, apiClient);
        console.log(`✅ Synced: ${action.type}`);
      } catch (error) {
        console.error(`❌ Failed to sync ${action.type}:`, error);
        failed.push(action);
      }
    }

    // Keep only failed actions in queue
    await AsyncStorage.setItem(OFFLINE_QUEUE_KEY, JSON.stringify(failed));

    if (failed.length === 0) {
      console.log("✅ All offline actions synced successfully");
    } else {
      console.log(`⚠️  ${failed.length} actions failed to sync`);
    }
  } catch (error) {
    console.error("Failed to sync queue:", error);
  }
}

/**
 * Process individual action
 */
async function processAction(
  action: OfflineAction,
  apiClient: any,
): Promise<void> {
  switch (action.type) {
    case "UPDATE_LOCATION":
      await apiClient.updateLocation(action.data);
      break;
    case "VOICE_COMMAND":
      await apiClient.submitVoiceCommand(action.data);
      break;
    case "UPDATE_SHIPMENT_STATUS":
      await apiClient.updateShipmentStatus(
        action.data.shipmentId,
        action.data.status,
      );
      break;
    default:
      console.warn(`Unknown action type: ${action.type}`);
  }
}

/**
 * Setup automatic sync when connection restored
 */
export function setupAutoSync(apiClient: any): () => void {
  const unsubscribe = NetInfo.addEventListener((state) => {
    if (state.isConnected && state.isInternetReachable) {
      console.log("📶 Connection restored, syncing...");
      syncQueue(apiClient);
    }
  });

  return unsubscribe;
}

/**
 * Clear all cached data
 */
export async function clearCache(): Promise<void> {
  try {
    await AsyncStorage.multiRemove([OFFLINE_QUEUE_KEY, CACHED_DATA_KEY]);
    console.log("🗑️  Cache cleared");
  } catch (error) {
    console.error("Failed to clear cache:", error);
  }
}

export default {
  isOnline,
  cacheData,
  getCachedData,
  queueAction,
  syncQueue,
  setupAutoSync,
  clearCache,
};
