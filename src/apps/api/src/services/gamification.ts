/**
 * Phase 3 Feature 4: Gamification System
 * Points engine, badge system, and leaderboards for driver engagement
 *
 * Expected Impact:
 * - 25% increase in driver engagement
 * - 15% improvement in customer retention
 * - Competitive motivation through real-time leaderboards
 */

export interface PointsEvent {
  driverId: string;
  category:
    | "on-time"
    | "safety"
    | "efficiency"
    | "customer-rating"
    | "milestone";
  points: number;
  metadata?: any;
}

export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
  requirement: string;
  pointValue: number;
}

export interface LeaderboardEntry {
  rank: number;
  driverId: string;
  driverName: string;
  totalPoints: number;
  badges: string[];
  trend: "up" | "down" | "stable";
}

export class GamificationEngine {
  // Badge definitions
  private readonly badges: Record<string, Badge> = {
    GOLD_STAR: {
      id: "GOLD_STAR",
      name: "Gold Star",
      description: "100 on-time deliveries",
      icon: "⭐",
      requirement: "100_on_time",
      pointValue: 500,
    },
    PERFECT_RECORD: {
      id: "PERFECT_RECORD",
      name: "Perfect Record",
      description: "No incidents for 6 months",
      icon: "🏆",
      requirement: "180_days_safe",
      pointValue: 1000,
    },
    SPEED_DEMON: {
      id: "SPEED_DEMON",
      name: "Speed Demon",
      description: "50 deliveries under estimated time",
      icon: "⚡",
      requirement: "50_early",
      pointValue: 300,
    },
    SAFETY_FIRST: {
      id: "SAFETY_FIRST",
      name: "Safety First",
      description: "Zero speeding violations for 3 months",
      icon: "🛡️",
      requirement: "90_days_no_speeding",
      pointValue: 400,
    },
    EFFICIENCY_MASTER: {
      id: "EFFICIENCY_MASTER",
      name: "Efficiency Master",
      description: "Average 20% fuel efficiency improvement",
      icon: "💚",
      requirement: "20_percent_fuel_savings",
      pointValue: 600,
    },
    CUSTOMER_FAVORITE: {
      id: "CUSTOMER_FAVORITE",
      name: "Customer Favorite",
      description: "50 deliveries with 5-star ratings",
      icon: "❤️",
      requirement: "50_five_star",
      pointValue: 350,
    },
    MARATHON_RUNNER: {
      id: "MARATHON_RUNNER",
      name: "Marathon Runner",
      description: "10,000 km driven safely",
      icon: "🏃",
      requirement: "10000_km_safe",
      pointValue: 800,
    },
    EARLY_BIRD: {
      id: "EARLY_BIRD",
      name: "Early Bird",
      description: "30 consecutive on-time pickups",
      icon: "🐦",
      requirement: "30_consecutive_on_time",
      pointValue: 250,
    },
  };

  // Points calculation rules
  private readonly pointsRules = {
    "on-time": 20, // On-time delivery
    early: 30, // Early delivery
    safety: 50, // No incidents/violations
    efficiency: 40, // Fuel efficiency achieved
    "customer-rating-5": 50, // 5-star customer rating
    "customer-rating-4": 30, // 4-star customer rating
    "customer-rating-3": 10, // 3-star customer rating
    "milestone-100": 500, // 100 deliveries milestone
    "milestone-500": 2500, // 500 deliveries milestone
    "milestone-1000": 5000, // 1000 deliveries milestone
  };

  /**
   * Calculate points for a delivery event
   */
  calculatePoints(event: PointsEvent): number {
    const basePoints = this.pointsRules[event.category] || 0;

    // Apply multipliers based on metadata
    let multiplier = 1.0;

    if (event.metadata) {
      // Consecutive bonus (e.g., 5 on-time deliveries in a row)
      if (event.metadata.consecutiveCount >= 5) {
        multiplier += 0.5;
      }

      // Weekend/holiday bonus
      if (event.metadata.isWeekend || event.metadata.isHoliday) {
        multiplier += 0.3;
      }

      // High-priority load bonus
      if (event.metadata.priority === "high") {
        multiplier += 0.2;
      }
    }

    return Math.round(basePoints * multiplier);
  }

  /**
   * Check if driver qualifies for new badges
   */
  checkBadgeEligibility(driverStats: {
    onTimeCount: number;
    earlyCount: number;
    fiveStarCount: number;
    consecutiveOnTime: number;
    daysSinceIncident: number;
    daysSinceSpeedingViolation: number;
    totalKmDriven: number;
    avgFuelEfficiency: number;
  }): Badge[] {
    const earnedBadges: Badge[] = [];

    // Check GOLD_STAR
    if (driverStats.onTimeCount >= 100) {
      earnedBadges.push(this.badges.GOLD_STAR);
    }

    // Check PERFECT_RECORD
    if (driverStats.daysSinceIncident >= 180) {
      earnedBadges.push(this.badges.PERFECT_RECORD);
    }

    // Check SPEED_DEMON
    if (driverStats.earlyCount >= 50) {
      earnedBadges.push(this.badges.SPEED_DEMON);
    }

    // Check SAFETY_FIRST
    if (driverStats.daysSinceSpeedingViolation >= 90) {
      earnedBadges.push(this.badges.SAFETY_FIRST);
    }

    // Check EFFICIENCY_MASTER
    if (driverStats.avgFuelEfficiency >= 20) {
      earnedBadges.push(this.badges.EFFICIENCY_MASTER);
    }

    // Check CUSTOMER_FAVORITE
    if (driverStats.fiveStarCount >= 50) {
      earnedBadges.push(this.badges.CUSTOMER_FAVORITE);
    }

    // Check MARATHON_RUNNER
    if (driverStats.totalKmDriven >= 10000) {
      earnedBadges.push(this.badges.MARATHON_RUNNER);
    }

    // Check EARLY_BIRD
    if (driverStats.consecutiveOnTime >= 30) {
      earnedBadges.push(this.badges.EARLY_BIRD);
    }

    return earnedBadges;
  }

  /**
   * Calculate leaderboard rankings for a period
   */
  calculateLeaderboard(
    driverPoints: Map<
      string,
      { points: number; driverName: string; badges: string[] }
    >,
    previousRankings?: Map<string, number>,
  ): LeaderboardEntry[] {
    // Sort drivers by points descending
    const sortedDrivers = Array.from(driverPoints.entries()).sort(
      (a, b) => b[1].points - a[1].points,
    );

    return sortedDrivers.map(([driverId, data], index) => {
      const currentRank = index + 1;
      const previousRank = previousRankings?.get(driverId);

      let trend: "up" | "down" | "stable" = "stable";
      if (previousRank) {
        if (currentRank < previousRank) trend = "up";
        else if (currentRank > previousRank) trend = "down";
      }

      return {
        rank: currentRank,
        driverId,
        driverName: data.driverName,
        totalPoints: data.points,
        badges: data.badges,
        trend,
      };
    });
  }

  /**
   * Get milestone achievements
   */
  getMilestones(
    deliveryCount: number,
  ): { milestone: string; points: number }[] {
    const milestones: { milestone: string; points: number }[] = [];

    if (deliveryCount >= 100 && deliveryCount < 500) {
      milestones.push({ milestone: "100 Deliveries", points: 500 });
    }
    if (deliveryCount >= 500 && deliveryCount < 1000) {
      milestones.push({ milestone: "500 Deliveries", points: 2500 });
    }
    if (deliveryCount >= 1000) {
      milestones.push({ milestone: "1000 Deliveries", points: 5000 });
    }

    return milestones;
  }

  /**
   * Generate personalized achievement message
   */
  generateAchievementMessage(badge: Badge): string {
    const messages = {
      GOLD_STAR:
        "🎉 Amazing! You've achieved 100 on-time deliveries! You're a star performer!",
      PERFECT_RECORD:
        "🏆 Incredible! 6 months without any incidents. You're setting the standard for safety!",
      SPEED_DEMON:
        "⚡ Lightning fast! 50 early deliveries shows your efficiency and dedication!",
      SAFETY_FIRST:
        "🛡️ Safety Champion! 3 months of perfect driving. Keep up the excellent work!",
      EFFICIENCY_MASTER:
        "💚 Eco Warrior! Your 20% fuel efficiency improvement is saving the planet!",
      CUSTOMER_FAVORITE:
        "❤️ Customer Champion! 50 five-star ratings prove you deliver excellence!",
      MARATHON_RUNNER:
        "🏃 Road Warrior! 10,000 km of safe driving is a monumental achievement!",
      EARLY_BIRD:
        "🐦 Consistency King! 30 consecutive on-time pickups shows true professionalism!",
    };

    return (
      messages[badge.id] ||
      `🎊 Congratulations on earning the ${badge.name} badge!`
    );
  }

  /**
   * Get all available badges
   */
  getAllBadges(): Badge[] {
    return Object.values(this.badges);
  }

  /**
   * Get badge by ID
   */
  getBadge(badgeId: string): Badge | undefined {
    return this.badges[badgeId];
  }

  /**
   * Calculate weekly streak bonus
   */
  calculateStreakBonus(consecutiveDays: number): number {
    if (consecutiveDays >= 30) return 500;
    if (consecutiveDays >= 14) return 200;
    if (consecutiveDays >= 7) return 100;
    return 0;
  }

  /**
   * Get driver performance tier
   */
  getPerformanceTier(totalPoints: number): {
    tier: string;
    color: string;
    benefits: string[];
  } {
    if (totalPoints >= 10000) {
      return {
        tier: "Platinum",
        color: "#E5E4E2",
        benefits: [
          "Priority load assignments",
          "Flexible scheduling",
          "Exclusive rewards",
          "Premium support",
        ],
      };
    } else if (totalPoints >= 5000) {
      return {
        tier: "Gold",
        color: "#FFD700",
        benefits: [
          "Priority load assignments",
          "Flexible scheduling",
          "Bonus opportunities",
        ],
      };
    } else if (totalPoints >= 2000) {
      return {
        tier: "Silver",
        color: "#C0C0C0",
        benefits: ["Priority support", "Recognition bonuses"],
      };
    } else {
      return {
        tier: "Bronze",
        color: "#CD7F32",
        benefits: ["Standard benefits"],
      };
    }
  }
}

export const gamificationEngine = new GamificationEngine();
