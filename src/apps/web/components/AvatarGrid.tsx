import React from "react";
import styles from "../styles/avatars.module.css";

const cards = [
  {
    id: "genesis",
    title: "Genesis Core",
    subtitle: "Logistics AI Navigator",
    description: "Optimizes routes, loads, ETAs and capacity across fleets.",
    color: "linear-gradient(135deg,#ffcc33,#ff3366)",
  },
  {
    id: "aurum",
    title: "Aurum Dispatch",
    subtitle: "Dispatcher Co-pilot",
    description:
      "Monitors lanes, suggests bids and protects margins in real time.",
    color: "linear-gradient(135deg,#ff9966,#ff5e62)",
  },
  {
    id: "noir",
    title: "Noir Guardian",
    subtitle: "Risk and Compliance",
    description:
      "Watches for anomalies, fraud and safety risks across the network.",
    color: "linear-gradient(135deg,#3a1c71,#d76d77)",
  },
];

export function AvatarGrid() {
  return (
    <div className={styles.grid}>
      {cards.map((card) => (
        <div key={card.id} className={styles.card}>
          <div className={styles.blob} style={{ background: card.color }} />
          <div className="card-content">
            <div className={styles.avatar} style={{ background: card.color }}>
              {card.title[0]}
            </div>
            <h3 style={{ margin: 0, fontSize: "1.2rem", fontWeight: 700 }}>
              {card.title}
            </h3>
            <p className={styles.subtitle}>{card.subtitle}</p>
            <p className={styles.body}>{card.description}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
