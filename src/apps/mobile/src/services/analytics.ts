/**
 * Mobile Analytics Service
 * Firebase Analytics integration for React Native
 * Track user behavior, events, and conversions
 */

import analytics from "@react-native-firebase/analytics";
import { Platform } from "react-native";

/**
 * User properties for segmentation
 */
interface UserProperties {
  userId?: string;
  email?: string;
  role?: "driver" | "customer" | "admin";
  accountType?: "free" | "pro" | "enterprise";
  registrationDate?: string;
}

/**
 * Shipment tracking events
 */
interface ShipmentEvent {
  shipmentId: string;
  trackingNumber: string;
  status?: string;
  origin?: string;
  destination?: string;
  value?: number;
}

/**
 * Driver location events
 */
interface DriverLocationEvent {
  driverId: string;
  latitude: number;
  longitude: number;
  speed?: number;
  accuracy?: number;
}

/**
 * Analytics service class
 */
class AnalyticsService {
  private isEnabled: boolean = true;
  private userId: string | null = null;

  /**
   * Initialize analytics
   */
  async initialize(): Promise<void> {
    try {
      await analytics().setAnalyticsCollectionEnabled(true);
      console.log("✓ Firebase Analytics initialized");
    } catch (error) {
      console.error("Failed to initialize analytics:", error);
      this.isEnabled = false;
    }
  }

  /**
   * Enable/disable analytics
   */
  async setEnabled(enabled: boolean): Promise<void> {
    this.isEnabled = enabled;
    await analytics().setAnalyticsCollectionEnabled(enabled);
  }

  /**
   * Set user ID
   */
  async setUser(userId: string, properties?: UserProperties): Promise<void> {
    if (!this.isEnabled) return;

    try {
      this.userId = userId;
      await analytics().setUserId(userId);

      if (properties) {
        await analytics().setUserProperties(
          properties as Record<string, string>,
        );
      }
    } catch (error) {
      console.error("Failed to set user:", error);
    }
  }

  /**
   * Clear user data (on logout)
   */
  async clearUser(): Promise<void> {
    if (!this.isEnabled) return;

    try {
      this.userId = null;
      await analytics().setUserId(null);
      await analytics().resetAnalyticsData();
    } catch (error) {
      console.error("Failed to clear user:", error);
    }
  }

  /**
   * Track screen view
   */
  async logScreenView(screenName: string, screenClass?: string): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logScreenView({
        screen_name: screenName,
        screen_class: screenClass || screenName,
      });
    } catch (error) {
      console.error("Failed to log screen view:", error);
    }
  }

  /**
   * Track shipment tracking event
   */
  async logShipmentTracked(event: ShipmentEvent): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("shipment_tracked", {
        shipment_id: event.shipmentId,
        tracking_number: event.trackingNumber,
        status: event.status,
        origin: event.origin,
        destination: event.destination,
        value: event.value,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log shipment tracked:", error);
    }
  }

  /**
   * Track driver location update
   */
  async logDriverLocationUpdated(event: DriverLocationEvent): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("driver_location_updated", {
        driver_id: event.driverId,
        latitude: event.latitude,
        longitude: event.longitude,
        speed: event.speed,
        accuracy: event.accuracy,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log driver location:", error);
    }
  }

  /**
   * Track user login
   */
  async logLogin(
    method: "email" | "google" | "apple" | "biometric",
  ): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logLogin({ method });
    } catch (error) {
      console.error("Failed to log login:", error);
    }
  }

  /**
   * Track user signup
   */
  async logSignup(method: "email" | "google" | "apple"): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logSignUp({ method });
    } catch (error) {
      console.error("Failed to log signup:", error);
    }
  }

  /**
   * Track search
   */
  async logSearch(query: string, results: number): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("search", {
        search_term: query,
        results_count: results,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log search:", error);
    }
  }

  /**
   * Track shipment creation
   */
  async logShipmentCreated(shipmentId: string, value: number): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("shipment_created", {
        shipment_id: shipmentId,
        value,
        currency: "USD",
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log shipment created:", error);
    }
  }

  /**
   * Track shipment delivered
   */
  async logShipmentDelivered(
    shipmentId: string,
    value: number,
    duration: number,
  ): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("shipment_delivered", {
        shipment_id: shipmentId,
        value,
        currency: "USD",
        duration_hours: duration,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log shipment delivered:", error);
    }
  }

  /**
   * Track push notification received
   */
  async logNotificationReceived(notificationType: string): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("notification_received", {
        notification_type: notificationType,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log notification:", error);
    }
  }

  /**
   * Track push notification opened
   */
  async logNotificationOpened(notificationType: string): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("notification_opened", {
        notification_type: notificationType,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log notification opened:", error);
    }
  }

  /**
   * Track app rating
   */
  async logAppRated(rating: number): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("app_rated", {
        rating,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log app rating:", error);
    }
  }

  /**
   * Track error
   */
  async logError(
    errorType: string,
    errorMessage: string,
    screen?: string,
  ): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("app_error", {
        error_type: errorType,
        error_message: errorMessage,
        screen,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log error:", error);
    }
  }

  /**
   * Track offline mode
   */
  async logOfflineMode(enabled: boolean): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("offline_mode", {
        enabled,
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log offline mode:", error);
    }
  }

  /**
   * Track custom event
   */
  async logCustomEvent(
    eventName: string,
    params?: Record<string, any>,
  ): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent(eventName, {
        ...params,
        platform: Platform.OS,
        user_id: this.userId,
      });
    } catch (error) {
      console.error("Failed to log custom event:", error);
    }
  }

  /**
   * Track conversion event (for paid features)
   */
  async logConversion(feature: string, value: number): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logEvent("conversion", {
        feature,
        value,
        currency: "USD",
        platform: Platform.OS,
      });
    } catch (error) {
      console.error("Failed to log conversion:", error);
    }
  }

  /**
   * Set current screen (for automatic tracking)
   */
  async setCurrentScreen(screenName: string): Promise<void> {
    if (!this.isEnabled) return;

    try {
      await analytics().logScreenView({
        screen_name: screenName,
        screen_class: screenName,
      });
    } catch (error) {
      console.error("Failed to set current screen:", error);
    }
  }
}

// Singleton instance
const analyticsService = new AnalyticsService();
export default analyticsService;

/**
 * Usage:
 *
 * // In App.tsx
 * import analyticsService from './services/analytics';
 *
 * useEffect(() => {
 *   analyticsService.initialize();
 * }, []);
 *
 * // Set user on login
 * await analyticsService.setUser(user.id, {
 *   email: user.email,
 *   role: 'driver',
 *   accountType: 'pro',
 * });
 *
 * // Track shipment tracking
 * await analyticsService.logShipmentTracked({
 *   shipmentId: shipment.id,
 *   trackingNumber: shipment.trackingNumber,
 *   status: shipment.status,
 * });
 *
 * // Track screen views (automatic with navigation)
 * navigation.addListener('state', () => {
 *   const route = navigationRef.getCurrentRoute();
 *   analyticsService.logScreenView(route.name);
 * });
 *
 * // Clear user on logout
 * await analyticsService.clearUser();
 *
 * Firebase Console Dashboard:
 * - Real-time active users
 * - Top screens
 * - User demographics
 * - Conversion funnels
 * - Retention cohorts
 * - Revenue analytics
 *
 * Expected metrics:
 * - Daily Active Users (DAU)
 * - Monthly Active Users (MAU)
 * - Session duration
 * - Screen flow
 * - Conversion rates
 * - User retention
 */
