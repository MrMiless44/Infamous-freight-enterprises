import React from "react";

/**
 * Error Boundary Component
 * Catches JavaScript errors anywhere in the component tree
 * Displays fallback UI and logs error details
 */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error to console and monitoring service
    console.error("Error Boundary caught an error:", error, errorInfo);

    this.setState({
      error,
      errorInfo,
    });

    // Send to error tracking service (Sentry, Datadog, etc.)
    if (typeof window !== "undefined" && window.Sentry) {
      window.Sentry.captureException(error, {
        contexts: {
          react: {
            componentStack: errorInfo.componentStack,
          },
        },
      });
    }

    // Send to Datadog RUM if available
    if (typeof window !== "undefined" && window.DD_RUM) {
      window.DD_RUM.addError(error, {
        type: "React Error Boundary",
        componentStack: errorInfo.componentStack,
      });
    }
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      const { fallback } = this.props;

      if (fallback) {
        return typeof fallback === "function"
          ? fallback(this.state.error, this.handleReset)
          : fallback;
      }

      // Default fallback UI
      return (
        <div
          style={{
            padding: "2rem",
            maxWidth: "600px",
            margin: "2rem auto",
            backgroundColor: "#fff",
            border: "1px solid #e5e7eb",
            borderRadius: "0.5rem",
            boxShadow: "0 1px 3px rgba(0, 0, 0, 0.1)",
          }}
        >
          <h1
            style={{
              fontSize: "1.5rem",
              fontWeight: "bold",
              color: "#dc2626",
              marginBottom: "1rem",
            }}
          >
            Oops! Something went wrong
          </h1>

          <p style={{ marginBottom: "1rem", color: "#4b5563" }}>
            We're sorry, but something unexpected happened. The error has been
            logged and we'll look into it.
          </p>

          {process.env.NODE_ENV === "development" && this.state.error && (
            <details
              style={{
                marginBottom: "1rem",
                padding: "1rem",
                backgroundColor: "#fef2f2",
                border: "1px solid #fecaca",
                borderRadius: "0.375rem",
              }}
            >
              <summary
                style={{
                  cursor: "pointer",
                  fontWeight: "600",
                  color: "#991b1b",
                }}
              >
                Error Details (Development Mode)
              </summary>
              <pre
                style={{
                  marginTop: "1rem",
                  fontSize: "0.875rem",
                  overflow: "auto",
                  color: "#7f1d1d",
                }}
              >
                {this.state.error.toString()}
                {this.state.errorInfo?.componentStack}
              </pre>
            </details>
          )}

          <div style={{ display: "flex", gap: "1rem" }}>
            <button
              onClick={this.handleReset}
              style={{
                padding: "0.5rem 1rem",
                backgroundColor: "#3b82f6",
                color: "white",
                border: "none",
                borderRadius: "0.375rem",
                cursor: "pointer",
                fontWeight: "500",
              }}
            >
              Try Again
            </button>

            <button
              onClick={() => (window.location.href = "/")}
              style={{
                padding: "0.5rem 1rem",
                backgroundColor: "#6b7280",
                color: "white",
                border: "none",
                borderRadius: "0.375rem",
                cursor: "pointer",
                fontWeight: "500",
              }}
            >
              Go Home
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
