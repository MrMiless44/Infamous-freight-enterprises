import React, { useEffect, useState } from "react";
import {
  SafeAreaView,
  StyleSheet,
  Text,
  View,
  FlatList,
  TouchableOpacity,
} from "react-native";
import * as SecureStore from "expo-secure-store";
import { StatusBar } from "expo-status-bar";

type ShipmentItem = {
  id: string;
  destination: string;
  eta?: string;
};

const API_BASE =
  process.env.EXPO_PUBLIC_API_BASE || "http://localhost:4000/api";

export default function App() {
  const [shipments, setShipments] = useState<ShipmentItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const token = await SecureStore.getItemAsync("driver_token");
      const res = await fetch(`${API_BASE}/health`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });
      const json = await res.json();
      setShipments([
        {
          id: "seed",
          destination: "Atlanta, GA",
          eta: json.time,
        },
      ]);
    } catch (err) {
      const message = err instanceof Error ? err.message : "unknown";
      setError(message);
      console.warn("Unable to reach API", message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      <View style={styles.topRow}>
        <View>
          <Text style={styles.heading}>Driver Control</Text>
          <Text style={styles.subheading}>
            {loading
              ? "Contacting AI dispatcher…"
              : "Latest assignment snapshot"}
          </Text>
        </View>
        <TouchableOpacity
          style={[styles.pill, { opacity: loading ? 0.7 : 1 }]}
          onPress={fetchData}
          disabled={loading}
        >
          <Text style={styles.pillText}>
            {loading ? "Refreshing" : "Refresh"}
          </Text>
        </TouchableOpacity>
      </View>

      <View style={styles.metaCard}>
        <Text style={styles.metaTitle}>Ready to roll</Text>
        <Text style={styles.metaCopy}>
          AI dispatcher is tuned for driver-safe prompts. Tap any load to
          accept, or refresh to fetch new work.
        </Text>
        <Text style={[styles.metaCopy, { marginTop: 8 }]}>API: {API_BASE}</Text>
      </View>

      {error && (
        <View style={[styles.metaCard, { borderColor: "#ff7b7b" }]}>
          <Text style={[styles.metaTitle, { color: "#ff7b7b" }]}>Offline</Text>
          <Text style={styles.metaCopy}>
            We could not reach the dispatcher.
          </Text>
          <Text style={styles.metaCopy}>Try refresh or check connection.</Text>
        </View>
      )}
      <FlatList
        data={shipments}
        keyExtractor={(item: ShipmentItem) => item.id}
        renderItem={({ item }: { item: ShipmentItem }) => (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>{item.destination}</Text>
            <Text style={styles.cardMeta}>ETA: {item.eta || "pending"}</Text>
            <TouchableOpacity style={styles.button}>
              <Text style={styles.buttonText}>Accept Load</Text>
            </TouchableOpacity>
          </View>
        )}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#050509",
    padding: 24,
  },
  heading: {
    color: "#f9fafb",
    fontSize: 28,
    fontWeight: "700",
    marginBottom: 8,
  },
  subheading: {
    color: "rgba(249,250,251,0.7)",
    marginBottom: 20,
  },
  topRow: {
    flexDirection: "row",
    alignItems: "flex-start",
    justifyContent: "space-between",
    gap: 12,
  },
  card: {
    backgroundColor: "#0b0b12",
    padding: 16,
    borderRadius: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.04)",
  },
  cardTitle: {
    color: "#f9fafb",
    fontSize: 18,
    fontWeight: "600",
  },
  cardMeta: {
    color: "rgba(249,250,251,0.7)",
    marginTop: 4,
    marginBottom: 12,
  },
  metaCard: {
    backgroundColor: "#0b0b12",
    padding: 14,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.06)",
    marginBottom: 16,
  },
  metaTitle: {
    color: "#f9fafb",
    fontSize: 16,
    fontWeight: "600",
    marginBottom: 4,
  },
  metaCopy: {
    color: "rgba(249,250,251,0.75)",
  },
  button: {
    backgroundColor: "#ffcc33",
    paddingVertical: 10,
    borderRadius: 999,
    alignItems: "center",
  },
  buttonText: {
    fontWeight: "600",
    color: "#050509",
  },
  pill: {
    backgroundColor: "rgba(255,255,255,0.08)",
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.12)",
  },
  pillText: {
    color: "#f9fafb",
    fontWeight: "600",
  },
});
