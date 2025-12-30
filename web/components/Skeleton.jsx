import React from "react";

/**
 * Skeleton Loading Component
 * Provides visual placeholders while content is loading
 */
export const Skeleton = ({
  width = "100%",
  height = "1rem",
  borderRadius = "0.25rem",
  className = "",
}) => {
  return (
    <div
      className={`skeleton ${className}`}
      style={{
        width,
        height,
        borderRadius,
        backgroundColor: "#e5e7eb",
        animation: "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      }}
    />
  );
};

/**
 * Skeleton for text lines
 */
export const SkeletonText = ({ lines = 3, spacing = "0.5rem" }) => {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: spacing }}>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton
          key={index}
          height="1rem"
          width={index === lines - 1 ? "80%" : "100%"}
        />
      ))}
    </div>
  );
};

/**
 * Skeleton for card components
 */
export const SkeletonCard = () => {
  return (
    <div
      style={{
        padding: "1.5rem",
        backgroundColor: "white",
        border: "1px solid #e5e7eb",
        borderRadius: "0.5rem",
        boxShadow: "0 1px 3px rgba(0, 0, 0, 0.1)",
      }}
    >
      <Skeleton height="1.5rem" width="60%" style={{ marginBottom: "1rem" }} />
      <SkeletonText lines={3} />
      <div
        style={{
          display: "flex",
          gap: "0.5rem",
          marginTop: "1rem",
        }}
      >
        <Skeleton height="2rem" width="5rem" borderRadius="0.375rem" />
        <Skeleton height="2rem" width="5rem" borderRadius="0.375rem" />
      </div>
    </div>
  );
};

/**
 * Skeleton for table rows
 */
export const SkeletonTable = ({ rows = 5, columns = 4 }) => {
  return (
    <div
      style={{
        backgroundColor: "white",
        border: "1px solid #e5e7eb",
        borderRadius: "0.5rem",
        overflow: "hidden",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: `repeat(${columns}, 1fr)`,
          gap: "1rem",
          padding: "1rem",
          backgroundColor: "#f9fafb",
          borderBottom: "1px solid #e5e7eb",
        }}
      >
        {Array.from({ length: columns }).map((_, index) => (
          <Skeleton key={`header-${index}`} height="1rem" />
        ))}
      </div>

      {/* Rows */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div
          key={`row-${rowIndex}`}
          style={{
            display: "grid",
            gridTemplateColumns: `repeat(${columns}, 1fr)`,
            gap: "1rem",
            padding: "1rem",
            borderBottom:
              rowIndex < rows - 1 ? "1px solid #e5e7eb" : "none",
          }}
        >
          {Array.from({ length: columns }).map((_, colIndex) => (
            <Skeleton key={`cell-${rowIndex}-${colIndex}`} height="1rem" />
          ))}
        </div>
      ))}
    </div>
  );
};

/**
 * Skeleton for shipment list
 */
export const SkeletonShipmentList = ({ count = 5 }) => {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      {Array.from({ length: count }).map((_, index) => (
        <div
          key={index}
          style={{
            padding: "1rem",
            backgroundColor: "white",
            border: "1px solid #e5e7eb",
            borderRadius: "0.5rem",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              marginBottom: "0.75rem",
            }}
          >
            <Skeleton height="1.25rem" width="8rem" />
            <Skeleton height="1.25rem" width="5rem" borderRadius="9999px" />
          </div>
          <SkeletonText lines={2} spacing="0.5rem" />
        </div>
      ))}
    </div>
  );
};

/**
 * Skeleton for dashboard stats
 */
export const SkeletonStats = () => {
  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
        gap: "1rem",
      }}
    >
      {Array.from({ length: 4 }).map((_, index) => (
        <div
          key={index}
          style={{
            padding: "1.5rem",
            backgroundColor: "white",
            border: "1px solid #e5e7eb",
            borderRadius: "0.5rem",
          }}
        >
          <Skeleton height="1rem" width="50%" style={{ marginBottom: "1rem" }} />
          <Skeleton height="2rem" width="40%" />
        </div>
      ))}
    </div>
  );
};

// Add keyframe animation for pulse effect
if (typeof document !== "undefined") {
  const style = document.createElement("style");
  style.textContent = `
    @keyframes pulse {
      0%, 100% {
        opacity: 1;
      }
      50% {
        opacity: 0.5;
      }
    }
  `;
  document.head.appendChild(style);
}

export default Skeleton;
