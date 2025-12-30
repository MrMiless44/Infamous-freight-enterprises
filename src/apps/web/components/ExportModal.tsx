import React, { useState } from "react";
import type { Shipment } from "@infamous-freight/shared";

interface ExportModalProps {
  isOpen: boolean;
  shipments: Shipment[];
  onClose: () => void;
  onExport: (
    format: "csv" | "pdf" | "json",
    filtered?: boolean,
  ) => Promise<void>;
}

/**
 * Export Modal Component
 * Allows users to export shipments in multiple formats
 */
export function ExportModal({
  isOpen,
  shipments,
  onClose,
  onExport,
}: ExportModalProps) {
  const [selectedFormat, setSelectedFormat] = useState<"csv" | "pdf" | "json">(
    "csv",
  );
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [isExporting, setIsExporting] = useState(false);

  if (!isOpen) return null;

  const handleExport = async () => {
    setIsExporting(true);
    try {
      await onExport(selectedFormat, filterStatus !== "all");
      onClose();
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setIsExporting(false);
    }
  };

  const filteredCount =
    filterStatus === "all"
      ? shipments.length
      : shipments.filter((s) => s.status === filterStatus).length;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="rounded-lg bg-white shadow-lg max-w-md w-full mx-4">
        {/* Header */}
        <div className="border-b border-gray-200 p-6">
          <h2 className="text-xl font-semibold text-gray-900">
            Export Shipments
          </h2>
          <p className="mt-1 text-sm text-gray-600">
            Download {filteredCount} shipment{filteredCount !== 1 ? "s" : ""}
          </p>
        </div>

        {/* Body */}
        <div className="space-y-6 p-6">
          {/* Format Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-3">
              Export Format
            </label>
            <div className="space-y-2">
              {["csv", "pdf", "json"].map((format) => (
                <label
                  key={format}
                  className="flex items-center p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-gray-50"
                >
                  <input
                    type="radio"
                    name="format"
                    value={format}
                    checked={selectedFormat === format}
                    onChange={(e) =>
                      setSelectedFormat(
                        e.target.value as "csv" | "pdf" | "json",
                      )
                    }
                    className="mr-3"
                  />
                  <div>
                    <p className="font-medium text-gray-900">
                      {format.toUpperCase()}
                    </p>
                    <p className="text-xs text-gray-500">
                      {format === "csv" &&
                        "Spreadsheet format, opens in Excel or Sheets"}
                      {format === "pdf" &&
                        "Professional report with statistics"}
                      {format === "json" && "Raw data format with metadata"}
                    </p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Status Filter */}
          <div>
            <label
              htmlFor="status"
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Filter by Status (Optional)
            </label>
            <select
              id="status"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="block w-full rounded-lg border border-gray-300 px-3 py-2 text-gray-900 focus:border-blue-500 focus:ring-blue-500"
            >
              <option value="all">All Shipments ({shipments.length})</option>
              <option value="pending">
                Pending (
                {shipments.filter((s) => s.status === "pending").length})
              </option>
              <option value="in_transit">
                In Transit (
                {shipments.filter((s) => s.status === "in_transit").length})
              </option>
              <option value="delivered">
                Delivered (
                {shipments.filter((s) => s.status === "delivered").length})
              </option>
            </select>
          </div>

          {/* Info Box */}
          <div className="rounded-lg bg-blue-50 p-3 text-sm text-blue-900">
            💡 Your export will be processed and downloaded automatically.
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-gray-200 flex gap-3 p-6">
          <button
            onClick={onClose}
            disabled={isExporting}
            className="flex-1 rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="flex-1 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isExporting ? (
              <>
                <span className="animate-spin">⌛</span> Exporting...
              </>
            ) : (
              <>📥 Export as {selectedFormat.toUpperCase()}</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Export Button Component
 * Quick access to export functionality
 */
export function ExportButton({
  shipments,
  onExport,
}: {
  shipments: Shipment[];
  onExport: (format: "csv" | "pdf" | "json") => Promise<void>;
}) {
  const [isModalOpen, setIsModalOpen] = useState(false);

  return (
    <>
      <button
        onClick={() => setIsModalOpen(true)}
        className="inline-flex items-center gap-2 rounded-lg bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 transition-colors"
        title="Download shipments in CSV, PDF, or JSON format"
      >
        📥 Export ({shipments.length})
      </button>

      <ExportModal
        isOpen={isModalOpen}
        shipments={shipments}
        onClose={() => setIsModalOpen(false)}
        onExport={async (format, filtered) => {
          await onExport(format);
        }}
      />
    </>
  );
}

export default ExportButton;
