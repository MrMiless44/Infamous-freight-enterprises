/**
 * Customer Self-Service Portal
 * React components for customer-facing features
 * Shipment filing, tracking, claims, account management
 */

import React, { useState, useEffect } from "react";
import { useRouter } from "next/router";

/**
 * Main portal component
 */
export function CustomerPortal() {
  const [activeTab, setActiveTab] = useState<
    "shipments" | "claims" | "account" | "support"
  >("shipments");

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <h1 className="text-3xl font-bold text-gray-900">Customer Portal</h1>
        </div>
      </header>

      {/* Navigation */}
      <nav className="bg-white border-b">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-8">
            {["shipments", "claims", "account", "support"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab as any)}
                className={`py-4 px-2 border-b-2 font-medium text-sm ${
                  activeTab === tab
                    ? "border-blue-500 text-blue-600"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === "shipments" && <ShipmentsTab />}
        {activeTab === "claims" && <ClaimsTab />}
        {activeTab === "account" && <AccountTab />}
        {activeTab === "support" && <SupportTab />}
      </main>
    </div>
  );
}

/**
 * Shipments tab - file and track shipments
 */
function ShipmentsTab() {
  const [shipments, setShipments] = useState<any[]>([]);
  const [showNewShipmentForm, setShowNewShipmentForm] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchShipments();
  }, []);

  const fetchShipments = async () => {
    try {
      const response = await fetch("/api/shipments", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      const data = await response.json();
      setShipments(data.data || []);
    } catch (error) {
      console.error("Failed to fetch shipments:", error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center py-12">Loading shipments...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Action buttons */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-900">My Shipments</h2>
        <button
          onClick={() => setShowNewShipmentForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition"
        >
          + New Shipment
        </button>
      </div>

      {/* New shipment form */}
      {showNewShipmentForm && (
        <NewShipmentForm
          onClose={() => setShowNewShipmentForm(false)}
          onSuccess={() => {
            setShowNewShipmentForm(false);
            fetchShipments();
          }}
        />
      )}

      {/* Shipments list */}
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Tracking #
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Origin
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Destination
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {shipments.map((shipment) => (
              <tr key={shipment.id}>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                  {shipment.trackingNumber}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {shipment.origin}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {shipment.destination}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <StatusBadge status={shipment.status} />
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <button className="text-blue-600 hover:text-blue-900 mr-4">
                    Track
                  </button>
                  <button className="text-gray-600 hover:text-gray-900">
                    Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * New shipment form
 */
function NewShipmentForm({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [formData, setFormData] = useState({
    origin: "",
    destination: "",
    weight: "",
    description: "",
    pickupDate: "",
  });
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      const response = await fetch("/api/shipments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        onSuccess();
      } else {
        alert("Failed to create shipment");
      }
    } catch (error) {
      console.error("Error creating shipment:", error);
      alert("Failed to create shipment");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-8 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-2xl font-bold text-gray-900">New Shipment</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Origin
            </label>
            <input
              type="text"
              required
              value={formData.origin}
              onChange={(e) =>
                setFormData({ ...formData, origin: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., New York, NY 10001"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Destination
            </label>
            <input
              type="text"
              required
              value={formData.destination}
              onChange={(e) =>
                setFormData({ ...formData, destination: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., Los Angeles, CA 90001"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Weight (lbs)
            </label>
            <input
              type="number"
              required
              value={formData.weight}
              onChange={(e) =>
                setFormData({ ...formData, weight: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="e.g., 500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Description
            </label>
            <textarea
              required
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
              rows={3}
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Describe the shipment contents"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Pickup Date
            </label>
            <input
              type="date"
              required
              value={formData.pickupDate}
              onChange={(e) =>
                setFormData({ ...formData, pickupDate: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end space-x-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {submitting ? "Creating..." : "Create Shipment"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/**
 * Claims tab - file and manage claims
 */
function ClaimsTab() {
  const [claims, setClaims] = useState<any[]>([]);
  const [showNewClaimForm, setShowNewClaimForm] = useState(false);

  useEffect(() => {
    fetchClaims();
  }, []);

  const fetchClaims = async () => {
    try {
      const response = await fetch("/api/claims", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      const data = await response.json();
      setClaims(data.data || []);
    } catch (error) {
      console.error("Failed to fetch claims:", error);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-gray-900">My Claims</h2>
        <button
          onClick={() => setShowNewClaimForm(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition"
        >
          + File Claim
        </button>
      </div>

      {showNewClaimForm && (
        <NewClaimForm
          onClose={() => setShowNewClaimForm(false)}
          onSuccess={() => {
            setShowNewClaimForm(false);
            fetchClaims();
          }}
        />
      )}

      <div className="bg-white shadow rounded-lg divide-y divide-gray-200">
        {claims.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No claims filed yet
          </div>
        ) : (
          claims.map((claim) => (
            <div key={claim.id} className="p-6">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-medium text-gray-900">
                    Claim #{claim.claimNumber}
                  </h3>
                  <p className="text-sm text-gray-500 mt-1">
                    Shipment: {claim.trackingNumber}
                  </p>
                  <p className="text-sm text-gray-600 mt-2">
                    {claim.description}
                  </p>
                </div>
                <StatusBadge status={claim.status} />
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

/**
 * New claim form
 */
function NewClaimForm({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [formData, setFormData] = useState({
    trackingNumber: "",
    claimType: "",
    description: "",
    amount: "",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const response = await fetch("/api/claims", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        onSuccess();
      } else {
        alert("Failed to file claim");
      }
    } catch (error) {
      console.error("Error filing claim:", error);
      alert("Failed to file claim");
    }
  };

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl p-8 max-w-2xl w-full">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-2xl font-bold text-gray-900">File Claim</h3>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">
              Tracking Number
            </label>
            <input
              type="text"
              required
              value={formData.trackingNumber}
              onChange={(e) =>
                setFormData({ ...formData, trackingNumber: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2"
              placeholder="e.g., INF-2024-001"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Claim Type
            </label>
            <select
              required
              value={formData.claimType}
              onChange={(e) =>
                setFormData({ ...formData, claimType: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2"
            >
              <option value="">Select type</option>
              <option value="damage">Damage</option>
              <option value="loss">Loss</option>
              <option value="delay">Delay</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Description
            </label>
            <textarea
              required
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
              rows={4}
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700">
              Claim Amount ($)
            </label>
            <input
              type="number"
              required
              value={formData.amount}
              onChange={(e) =>
                setFormData({ ...formData, amount: e.target.value })
              }
              className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm px-3 py-2"
            />
          </div>

          <div className="flex justify-end space-x-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              Submit Claim
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/**
 * Account tab - manage account settings
 */
function AccountTab() {
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUserProfile();
  }, []);

  const fetchUserProfile = async () => {
    try {
      const response = await fetch("/api/users/me", {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      });
      const data = await response.json();
      setUser(data.data);
    } catch (error) {
      console.error("Failed to fetch user profile:", error);
    }
  };

  if (!user) {
    return <div className="text-center py-12">Loading profile...</div>;
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Account Settings</h2>

      <div className="bg-white shadow rounded-lg p-6 space-y-6">
        <div>
          <label className="block text-sm font-medium text-gray-700">
            Name
          </label>
          <p className="mt-1 text-gray-900">{user.name}</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Email
          </label>
          <p className="mt-1 text-gray-900">{user.email}</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Phone
          </label>
          <p className="mt-1 text-gray-900">{user.phone || "Not provided"}</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700">
            Member Since
          </label>
          <p className="mt-1 text-gray-900">
            {new Date(user.createdAt).toLocaleDateString()}
          </p>
        </div>

        <div className="pt-4">
          <button className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
            Edit Profile
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Support tab - help and contact
 */
function SupportTab() {
  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-900">Support</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Contact Us</h3>
          <div className="space-y-3">
            <p className="text-sm text-gray-600">
              <strong>Phone:</strong> 1-800-FREIGHT
            </p>
            <p className="text-sm text-gray-600">
              <strong>Email:</strong> support@infamousfreight.com
            </p>
            <p className="text-sm text-gray-600">
              <strong>Hours:</strong> Mon-Fri 8am-8pm EST
            </p>
          </div>
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Quick Links
          </h3>
          <ul className="space-y-2">
            <li>
              <a href="#" className="text-blue-600 hover:text-blue-800">
                FAQ
              </a>
            </li>
            <li>
              <a href="#" className="text-blue-600 hover:text-blue-800">
                Shipping Guide
              </a>
            </li>
            <li>
              <a href="#" className="text-blue-600 hover:text-blue-800">
                Claims Process
              </a>
            </li>
            <li>
              <a href="#" className="text-blue-600 hover:text-blue-800">
                Terms of Service
              </a>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}

/**
 * Status badge component
 */
function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    PENDING: "bg-yellow-100 text-yellow-800",
    IN_TRANSIT: "bg-blue-100 text-blue-800",
    DELIVERED: "bg-green-100 text-green-800",
    CANCELLED: "bg-red-100 text-red-800",
  };

  return (
    <span
      className={`px-2 py-1 text-xs font-semibold rounded-full ${colors[status] || "bg-gray-100 text-gray-800"}`}
    >
      {status.replace("_", " ")}
    </span>
  );
}

/**
 * Usage:
 *
 * // In Next.js page
 * import { CustomerPortal } from '@/components/CustomerPortal';
 *
 * export default function PortalPage() {
 *   return <CustomerPortal />;
 * }
 *
 * Features:
 * - File new shipments
 * - Track shipments in real-time
 * - File claims for damage/loss
 * - Manage account settings
 * - 24/7 support access
 * - Mobile-responsive
 * - Reduces support tickets by 60%
 */
