import React, { useEffect, useState } from "react";
import { SafeAreaView, StyleSheet, Text, View, FlatList, TouchableOpacity } from "react-native";
import * as SecureStore from "expo-secure-store";
import { StatusBar } from "expo-status-bar";

type ShipmentItem = {
  id: string;
  destination: string;
  eta?: string;
};

const API_BASE = process.env.EXPO_PUBLIC_API_BASE || "http://localhost:4000/api";

export default function App() {
  const [shipments, setShipments] = useState<ShipmentItem[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const bootstrap = async () => {
      setLoading(true);
      try {
        const token = await SecureStore.getItemAsync("driver_token");
        const res = await fetch(`${API_BASE}/health`, {
          headers: token ? { Authorization: `Bearer ${token}` } : undefined
        });
        const json = await res.json();
        setShipments([
          {
            id: "seed",
            destination: "Atlanta, GA",
            eta: json.time
          }
        ]);
      } catch (err) {
        const message = err instanceof Error ? err.message : "unknown";
        console.warn("Unable to reach API", message);
      } finally {
        setLoading(false);
      }
    };

    bootstrap();
  }, []);

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      <Text style={styles.heading}>Driver Control</Text>
      <Text style={styles.subheading}>
        {loading ? "Contacting AI dispatcher…" : "Latest assignment snapshot"}
      </Text>
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
    padding: 24
  },
  heading: {
    color: "#f9fafb",
    fontSize: 28,
    fontWeight: "700",
    marginBottom: 8
  },
  subheading: {
    color: "rgba(249,250,251,0.7)",
    marginBottom: 20
  },
  card: {
    backgroundColor: "#0b0b12",
    padding: 16,
    borderRadius: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: "rgba(255,255,255,0.04)"
  },
  cardTitle: {
    color: "#f9fafb",
    fontSize: 18,
    fontWeight: "600"
  },
  cardMeta: {
    color: "rgba(249,250,251,0.7)",
    marginTop: 4,
    marginBottom: 12
  },
  button: {
    backgroundColor: "#ffcc33",
    paddingVertical: 10,
    borderRadius: 999,
    alignItems: "center"
  },
  buttonText: {
    fontWeight: "600",
    color: "#050509"
  }
});
