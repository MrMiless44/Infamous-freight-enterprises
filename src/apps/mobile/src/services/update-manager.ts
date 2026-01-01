/**
 * Over-The-Air (OTA) Update Strategy
 * Seamlessly push updates without app store review
 * Using Expo Updates for instant JavaScript bundle updates
 */

import * as Updates from "expo-updates";
import { Alert, AppState, AppStateStatus } from "react-native";
import AsyncStorage from "@react-native-async-storage/async-storage";
import analyticsService from "./analytics";

/**
 * Update configuration
 */
interface UpdateConfig {
  checkOnLaunch: boolean;
  checkOnResume: boolean;
  autoDownload: boolean;
  checkInterval: number; // milliseconds
  fallbackToCacheTimeout: number;
}

const DEFAULT_CONFIG: UpdateConfig = {
  checkOnLaunch: true,
  checkOnResume: true,
  autoDownload: true,
  checkInterval: 30 * 60 * 1000, // 30 minutes
  fallbackToCacheTimeout: 30000, // 30 seconds
};

/**
 * Update manager class
 */
class UpdateManager {
  private config: UpdateConfig;
  private checkInterval: NodeJS.Timeout | null = null;
  private appStateSubscription: any = null;

  constructor(config: Partial<UpdateConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Initialize update checking
   */
  async initialize(): Promise<void> {
    // Don't check in development
    if (__DEV__) {
      console.log("⚠️ OTA updates disabled in development");
      return;
    }

    console.log("🔄 Initializing OTA update manager");

    // Check on app launch
    if (this.config.checkOnLaunch) {
      await this.checkForUpdates();
    }

    // Check periodically
    this.startPeriodicChecks();

    // Check when app resumes
    if (this.config.checkOnResume) {
      this.listenForAppStateChanges();
    }

    // Log current update info
    await this.logCurrentVersion();
  }

  /**
   * Check for available updates
   */
  async checkForUpdates(): Promise<boolean> {
    try {
      console.log("🔍 Checking for updates...");

      const update = await Updates.checkForUpdateAsync();

      if (update.isAvailable) {
        console.log("✅ Update available");

        analyticsService.logCustomEvent("update_available", {
          currentVersion: Updates.manifest?.version,
          updateId: update.manifest?.id,
        });

        if (this.config.autoDownload) {
          await this.downloadAndInstallUpdate();
        } else {
          this.promptUserForUpdate();
        }

        return true;
      } else {
        console.log("✓ App is up to date");
        return false;
      }
    } catch (error) {
      console.error("Failed to check for updates:", error);
      analyticsService.logError("update_check_failed", error.message);
      return false;
    }
  }

  /**
   * Download and install update
   */
  private async downloadAndInstallUpdate(): Promise<void> {
    try {
      console.log("⬇️ Downloading update...");

      const result = await Updates.fetchUpdateAsync();

      if (result.isNew) {
        console.log("✅ Update downloaded");

        analyticsService.logCustomEvent("update_downloaded", {
          updateId: result.manifest?.id,
        });

        // Ask user to restart
        this.promptUserToRestart();
      }
    } catch (error) {
      console.error("Failed to download update:", error);
      analyticsService.logError("update_download_failed", error.message);
    }
  }

  /**
   * Prompt user to download update
   */
  private promptUserForUpdate(): void {
    Alert.alert(
      "Update Available",
      "A new version is available. Would you like to download it now?",
      [
        { text: "Later", style: "cancel" },
        {
          text: "Download",
          onPress: async () => {
            await this.downloadAndInstallUpdate();
          },
        },
      ],
    );
  }

  /**
   * Prompt user to restart app
   */
  private promptUserToRestart(): void {
    Alert.alert(
      "Update Ready",
      "The update has been downloaded. Restart the app to apply changes.",
      [
        { text: "Later", style: "cancel" },
        {
          text: "Restart Now",
          onPress: async () => {
            await Updates.reloadAsync();
          },
        },
      ],
    );
  }

  /**
   * Force reload to latest update
   */
  async forceUpdate(): Promise<void> {
    try {
      await Updates.reloadAsync();
    } catch (error) {
      console.error("Failed to reload app:", error);
    }
  }

  /**
   * Rollback to previous version
   */
  async rollback(): Promise<void> {
    try {
      console.log("⏮️ Rolling back to previous version...");

      // Expo Updates doesn't support automatic rollback
      // Manual approach: Clear update cache
      await Updates.clearUpdateCacheExperimentalAsync();
      await Updates.reloadAsync();

      analyticsService.logCustomEvent("update_rollback", {
        reason: "manual",
      });
    } catch (error) {
      console.error("Failed to rollback:", error);
    }
  }

  /**
   * Start periodic update checks
   */
  private startPeriodicChecks(): void {
    this.checkInterval = setInterval(async () => {
      await this.checkForUpdates();
    }, this.config.checkInterval);
  }

  /**
   * Stop periodic checks
   */
  stopPeriodicChecks(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
  }

  /**
   * Listen for app state changes
   */
  private listenForAppStateChanges(): void {
    this.appStateSubscription = AppState.addEventListener(
      "change",
      async (nextAppState: AppStateStatus) => {
        if (nextAppState === "active") {
          await this.checkForUpdates();
        }
      },
    );
  }

  /**
   * Get current version info
   */
  async getCurrentVersion(): Promise<{
    version: string;
    updateId: string;
    channel: string;
  }> {
    return {
      version: Updates.manifest?.version || "unknown",
      updateId: Updates.updateId || "unknown",
      channel: Updates.channel || "default",
    };
  }

  /**
   * Log current version
   */
  private async logCurrentVersion(): Promise<void> {
    const version = await this.getCurrentVersion();
    console.log("📱 Current version:", version);

    await AsyncStorage.setItem("app_version", JSON.stringify(version));
  }

  /**
   * Check if emergency update is required
   */
  async checkEmergencyUpdate(): Promise<boolean> {
    try {
      // Fetch emergency update config from server
      const response = await fetch(
        `${process.env.EXPO_PUBLIC_API_URL}/api/mobile/emergency-update`,
      );
      const data = await response.json();

      if (data.forceUpdate && data.minVersion) {
        const currentVersion = Updates.manifest?.version;

        if (this.isVersionLower(currentVersion, data.minVersion)) {
          this.showEmergencyUpdateAlert(data.message);
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error("Failed to check emergency update:", error);
      return false;
    }
  }

  /**
   * Show emergency update alert (blocking)
   */
  private showEmergencyUpdateAlert(message: string): void {
    Alert.alert(
      "Update Required",
      message ||
        "This version is no longer supported. Please update to continue.",
      [
        {
          text: "Update Now",
          onPress: async () => {
            await this.downloadAndInstallUpdate();
          },
        },
      ],
      { cancelable: false },
    );
  }

  /**
   * Compare version numbers
   */
  private isVersionLower(current: string, minimum: string): boolean {
    const currentParts = current.split(".").map(Number);
    const minimumParts = minimum.split(".").map(Number);

    for (
      let i = 0;
      i < Math.max(currentParts.length, minimumParts.length);
      i++
    ) {
      const c = currentParts[i] || 0;
      const m = minimumParts[i] || 0;

      if (c < m) return true;
      if (c > m) return false;
    }

    return false;
  }

  /**
   * Cleanup
   */
  cleanup(): void {
    this.stopPeriodicChecks();
    if (this.appStateSubscription) {
      this.appStateSubscription.remove();
    }
  }
}

// Singleton instance
const updateManager = new UpdateManager();
export default updateManager;

/**
 * Usage:
 *
 * // In App.tsx
 * import updateManager from './services/update-manager';
 *
 * useEffect(() => {
 *   updateManager.initialize();
 *
 *   return () => {
 *     updateManager.cleanup();
 *   };
 * }, []);
 *
 * // Manual check
 * const hasUpdate = await updateManager.checkForUpdates();
 *
 * // Force update
 * await updateManager.forceUpdate();
 *
 * // Rollback
 * await updateManager.rollback();
 *
 * // Check emergency update
 * await updateManager.checkEmergencyUpdate();
 *
 * // app.json configuration
 * {
 *   "expo": {
 *     "updates": {
 *       "enabled": true,
 *       "checkAutomatically": "ON_LOAD",
 *       "fallbackToCacheTimeout": 30000,
 *       "url": "https://u.expo.dev/[project-id]"
 *     },
 *     "runtimeVersion": {
 *       "policy": "sdkVersion"
 *     }
 *   }
 * }
 *
 * // Publish update
 * eas update --branch production --message "Bug fixes"
 *
 * // Rollback update
 * eas update:rollback --branch production
 *
 * Expected benefits:
 * - Instant bug fixes (no app store review)
 * - Faster feature deployment
 * - Reduced app store submission cycles
 * - Better user experience (seamless updates)
 * - Emergency rollback capability
 *
 * Update strategy:
 * - Check on launch: immediate fixes
 * - Check on resume: catch updates while app running
 * - Periodic checks: ensure users stay current
 * - Emergency updates: force critical security patches
 */
