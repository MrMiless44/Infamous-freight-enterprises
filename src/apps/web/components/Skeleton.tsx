import React from 'react';

interface SkeletonProps {
  className?: string;
  count?: number;
  height?: number | string;
  width?: number | string;
  circle?: boolean;
}

const pulseStyles = `
  @keyframes pulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }
`;

/**
 * Base Skeleton Loader Component
 */
export const Skeleton: React.FC<SkeletonProps> = ({
  className = '',
  count = 1,
  height = '1rem',
  width = '100%',
  circle = false,
}) => {
  const items = Array.from({ length: count }, (_, i) => i);

  const skeletonStyle: React.CSSProperties = {
    backgroundColor: '#e5e7eb',
    borderRadius: circle ? '50%' : '0.375rem',
    height: typeof height === 'number' ? `${height}px` : height,
    width: typeof width === 'number' ? `${width}px` : width,
    animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
    marginBottom: '0.5rem',
  };

  return (
    <>
      <style>{pulseStyles}</style>
      {items.map((i) => (
        <div key={i} style={skeletonStyle} className={className} />
      ))}
    </>
  );
};

/**
 * Skeleton Text - Multiple lines of varying width
 */
export const SkeletonText: React.FC<SkeletonProps> = ({
  count = 3,
  height = '1rem',
  ...props
}) => {
  const items = Array.from({ length: count }, (_, i) => {
    // Vary width to look more natural
    const widths = ['100%', '95%', '85%'];
    return widths[i % widths.length];
  });

  return (
    <div>
      <style>{pulseStyles}</style>
      {items.map((width, i) => (
        <div
          key={i}
          style={{
            backgroundColor: '#e5e7eb',
            borderRadius: '0.375rem',
            height: typeof height === 'number' ? `${height}px` : height,
            width,
            marginBottom: '0.5rem',
            animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
          }}
          className={props.className}
        />
      ))}
    </div>
  );
};

/**
 * Skeleton Card - Simulates card layout with header, content, and footer
 */
export const SkeletonCard: React.FC<{ count?: number }> = ({ count = 1 }) => {
  const items = Array.from({ length: count }, (_, i) => i);

  return (
    <>
      <style>{pulseStyles}</style>
      {items.map((i) => (
        <div
          key={i}
          style={{
            padding: '1rem',
            border: '1px solid #e5e7eb',
            borderRadius: '0.5rem',
            marginBottom: '1rem',
            backgroundColor: '#f9fafb',
          }}
        >
          {/* Header */}
          <div
            style={{
              height: '1.5rem',
              width: '40%',
              backgroundColor: '#e5e7eb',
              borderRadius: '0.375rem',
              marginBottom: '1rem',
              animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            }}
          />

          {/* Content lines */}
          {[1, 2, 3].map((j) => (
            <div
              key={j}
              style={{
                height: '1rem',
                width: j === 3 ? '70%' : '100%',
                backgroundColor: '#e5e7eb',
                borderRadius: '0.375rem',
                marginBottom: '0.5rem',
                animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
              }}
            />
          ))}
        </div>
      ))}
    </>
  );
};

/**
 * Skeleton Table - Simulates table rows and columns
 */
export const SkeletonTable: React.FC<{
  rows?: number;
  columns?: number;
}> = ({ rows = 5, columns = 4 }) => {
  const rowArray = Array.from({ length: rows }, (_, i) => i);
  const colArray = Array.from({ length: columns }, (_, i) => i);

  return (
    <>
      <style>{pulseStyles}</style>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <tbody>
          {rowArray.map((i) => (
            <tr key={i} style={{ borderBottom: '1px solid #e5e7eb' }}>
              {colArray.map((j) => (
                <td key={j} style={{ padding: '1rem' }}>
                  <div
                    style={{
                      height: '1rem',
                      width: j === 0 ? '80%' : '100%',
                      backgroundColor: '#e5e7eb',
                      borderRadius: '0.375rem',
                      animation:
                        'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                    }}
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
};

/**
 * Skeleton Stats - Multiple stat cards
 */
export const SkeletonStats: React.FC<{ count?: number }> = ({ count = 4 }) => {
  const items = Array.from({ length: count }, (_, i) => i);

  return (
    <>
      <style>{pulseStyles}</style>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}
      >
        {items.map((i) => (
          <div
            key={i}
            style={{
              padding: '1rem',
              border: '1px solid #e5e7eb',
              borderRadius: '0.5rem',
              backgroundColor: '#f9fafb',
            }}
          >
            {/* Label */}
            <div
              style={{
                height: '0.875rem',
                width: '60%',
                backgroundColor: '#e5e7eb',
                borderRadius: '0.375rem',
                marginBottom: '0.75rem',
                animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
              }}
            />

            {/* Value */}
            <div
              style={{
                height: '2rem',
                width: '80%',
                backgroundColor: '#e5e7eb',
                borderRadius: '0.375rem',
                animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
              }}
            />
          </div>
        ))}
      </div>
    </>
  );
};

/**
 * Skeleton Shipment List - Specialized for shipment cards
 */
export const SkeletonShipmentList: React.FC<{ count?: number }> = ({
  count = 3,
}) => {
  const items = Array.from({ length: count }, (_, i) => i);

  return (
    <>
      <style>{pulseStyles}</style>
      <div style={{ gap: '1rem' }}>
        {items.map((i) => (
          <div
            key={i}
            style={{
              padding: '1rem',
              border: '1px solid #e5e7eb',
              borderRadius: '0.5rem',
              marginBottom: '1rem',
              backgroundColor: '#f9fafb',
            }}
          >
            {/* Shipment ID */}
            <div
              style={{
                height: '1.25rem',
                width: '30%',
                backgroundColor: '#e5e7eb',
                borderRadius: '0.375rem',
                marginBottom: '0.75rem',
                animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
              }}
            />

            {/* Details row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              {[1, 2].map((j) => (
                <div key={j}>
                  <div
                    style={{
                      height: '0.875rem',
                      width: '50%',
                      backgroundColor: '#e5e7eb',
                      borderRadius: '0.375rem',
                      marginBottom: '0.5rem',
                      animation:
                        'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                    }}
                  />
                  <div
                    style={{
                      height: '1rem',
                      width: '100%',
                      backgroundColor: '#e5e7eb',
                      borderRadius: '0.375rem',
                      animation:
                        'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                    }}
                  />
                </div>
              ))}
            </div>

            {/* Status badge */}
            <div
              style={{
                height: '1.5rem',
                width: '20%',
                backgroundColor: '#e5e7eb',
                borderRadius: '9999px',
                marginTop: '1rem',
                animation: 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
              }}
            />
          </div>
        ))}
      </div>
    </>
  );
};

export default Skeleton;
