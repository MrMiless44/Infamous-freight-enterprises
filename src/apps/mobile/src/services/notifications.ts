/**
 * Push Notifications Service (Expo)
 * Alerts drivers of new assignments
 */

import * as Notifications from "expo-notifications";
import * as Device from "expo-device";
import { Platform } from "react-native";
import Constants from "expo-constants";

// Configure notification handler
Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
  }),
});

/**
 * Register for push notifications
 */
export async function registerForPushNotifications(): Promise<string | null> {
  if (!Device.isDevice) {
    console.warn("Push notifications only work on physical devices");
    return null;
  }

  // Check existing permissions
  const { status: existingStatus } = await Notifications.getPermissionsAsync();
  let finalStatus = existingStatus;

  // Request permission if not granted
  if (existingStatus !== "granted") {
    const { status } = await Notifications.requestPermissionsAsync();
    finalStatus = status;
  }

  if (finalStatus !== "granted") {
    console.error("Failed to get push notification permissions");
    return null;
  }

  // Get push token
  try {
    const projectId = Constants.expoConfig?.extra?.eas?.projectId;

    if (!projectId) {
      throw new Error("Project ID not found in app.json");
    }

    const token = await Notifications.getExpoPushTokenAsync({
      projectId,
    });

    console.log("✅ Push token:", token.data);

    // Configure Android channel
    if (Platform.OS === "android") {
      await Notifications.setNotificationChannelAsync("default", {
        name: "default",
        importance: Notifications.AndroidImportance.MAX,
        vibrationPattern: [0, 250, 250, 250],
        lightColor: "#FF231F7C",
      });
    }

    return token.data;
  } catch (error) {
    console.error("Failed to get push token:", error);
    return null;
  }
}

/**
 * Send local notification
 */
export async function sendLocalNotification(
  title: string,
  body: string,
  data?: any,
): Promise<void> {
  await Notifications.scheduleNotificationAsync({
    content: {
      title,
      body,
      data,
      sound: true,
      priority: Notifications.AndroidNotificationPriority.HIGH,
    },
    trigger: null, // Show immediately
  });
}

/**
 * Handle notification tapped by user
 */
export function addNotificationResponseListener(
  callback: (response: Notifications.NotificationResponse) => void,
): Notifications.Subscription {
  return Notifications.addNotificationResponseReceivedListener(callback);
}

/**
 * Handle notification received while app is foregrounded
 */
export function addNotificationReceivedListener(
  callback: (notification: Notifications.Notification) => void,
): Notifications.Subscription {
  return Notifications.addNotificationReceivedListener(callback);
}

/**
 * Cancel all scheduled notifications
 */
export async function cancelAllNotifications(): Promise<void> {
  await Notifications.cancelAllScheduledNotificationsAsync();
  console.log("🗑️  All notifications cancelled");
}

/**
 * Get badge count
 */
export async function getBadgeCount(): Promise<number> {
  return await Notifications.getBadgeCountAsync();
}

/**
 * Set badge count
 */
export async function setBadgeCount(count: number): Promise<void> {
  await Notifications.setBadgeCountAsync(count);
}

/**
 * Clear badge
 */
export async function clearBadge(): Promise<void> {
  await Notifications.setBadgeCountAsync(0);
}

export default {
  registerForPushNotifications,
  sendLocalNotification,
  addNotificationResponseListener,
  addNotificationReceivedListener,
  cancelAllNotifications,
  getBadgeCount,
  setBadgeCount,
  clearBadge,
};
