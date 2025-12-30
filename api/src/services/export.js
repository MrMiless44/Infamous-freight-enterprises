const { Parser } = require("json2csv");
const PDFDocument = require("pdfkit");
const { logger } = require("../middleware/logger");

/**
 * Export shipments to CSV format
 * @param {Array} shipments - Array of shipment objects
 * @returns {string} CSV string
 */
function exportToCSV(shipments) {
  try {
    const fields = [
      { label: "ID", value: "id" },
      { label: "Reference", value: "reference" },
      { label: "Origin", value: "origin" },
      { label: "Destination", value: "destination" },
      { label: "Status", value: "status" },
      { label: "Driver ID", value: "driverId" },
      { label: "Driver Name", value: "driver.name" },
      { label: "Driver Phone", value: "driver.phone" },
      { label: "Created At", value: "createdAt" },
      { label: "Updated At", value: "updatedAt" },
    ];

    const parser = new Parser({ fields });
    const csv = parser.parse(shipments);

    logger.info("Shipments exported to CSV", { count: shipments.length });
    return csv;
  } catch (error) {
    logger.error("CSV export error", { error: error.message });
    throw new Error(`Failed to generate CSV: ${error.message}`);
  }
}

/**
 * Export shipments to PDF format
 * @param {Array} shipments - Array of shipment objects
 * @returns {Promise<Buffer>} PDF buffer
 */
async function exportToPDF(shipments) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({ margin: 50 });
      const buffers = [];

      doc.on("data", buffers.push.bind(buffers));
      doc.on("end", () => {
        const pdfBuffer = Buffer.concat(buffers);
        logger.info("Shipments exported to PDF", { count: shipments.length });
        resolve(pdfBuffer);
      });

      // Title
      doc
        .fontSize(20)
        .font("Helvetica-Bold")
        .text("Shipment Report", { align: "center" });

      doc.fontSize(10).text(`Generated: ${new Date().toLocaleString()}`, {
        align: "center",
      });

      doc.moveDown();

      // Summary
      const stats = {
        total: shipments.length,
        created: shipments.filter((s) => s.status === "created").length,
        in_transit: shipments.filter((s) => s.status === "in_transit").length,
        delivered: shipments.filter((s) => s.status === "delivered").length,
        cancelled: shipments.filter((s) => s.status === "cancelled").length,
      };

      doc
        .fontSize(12)
        .font("Helvetica-Bold")
        .text("Summary", { underline: true });
      doc.font("Helvetica").fontSize(10);
      doc.text(`Total Shipments: ${stats.total}`);
      doc.text(`Created: ${stats.created}`);
      doc.text(`In Transit: ${stats.in_transit}`);
      doc.text(`Delivered: ${stats.delivered}`);
      doc.text(`Cancelled: ${stats.cancelled}`);

      doc.moveDown();

      // Table header
      doc
        .fontSize(12)
        .font("Helvetica-Bold")
        .text("Shipment Details", { underline: true });
      doc.moveDown(0.5);

      // Shipment details
      shipments.forEach((shipment, index) => {
        if (doc.y > 700) {
          doc.addPage();
        }

        doc.fontSize(10).font("Helvetica-Bold");
        doc.text(`${index + 1}. ${shipment.reference}`, {
          continued: true,
          width: 200,
        });
        doc
          .font("Helvetica")
          .text(` - Status: ${shipment.status}`, { align: "left" });

        doc.fontSize(9).font("Helvetica");
        doc.text(`   Origin: ${shipment.origin}`);
        doc.text(`   Destination: ${shipment.destination}`);

        if (shipment.driver) {
          doc.text(`   Driver: ${shipment.driver.name || "N/A"} ${shipment.driver.phone ? `(${shipment.driver.phone})` : ""}`);
        }

        doc.text(
          `   Created: ${new Date(shipment.createdAt).toLocaleDateString()}`,
        );
        doc.moveDown(0.5);
      });

      // Footer
      const pages = doc.bufferedPageRange();
      for (let i = 0; i < pages.count; i++) {
        doc.switchToPage(i);
        doc
          .fontSize(8)
          .text(
            `Page ${i + 1} of ${pages.count}`,
            50,
            doc.page.height - 50,
            { align: "center" },
          );
      }

      doc.end();
    } catch (error) {
      logger.error("PDF export error", { error: error.message });
      reject(new Error(`Failed to generate PDF: ${error.message}`));
    }
  });
}

/**
 * Export shipments to JSON format
 * @param {Array} shipments - Array of shipment objects
 * @returns {string} JSON string
 */
function exportToJSON(shipments) {
  try {
    const json = JSON.stringify(
      {
        exportDate: new Date().toISOString(),
        count: shipments.length,
        shipments,
      },
      null,
      2,
    );

    logger.info("Shipments exported to JSON", { count: shipments.length });
    return json;
  } catch (error) {
    logger.error("JSON export error", { error: error.message });
    throw new Error(`Failed to generate JSON: ${error.message}`);
  }
}

module.exports = {
  exportToCSV,
  exportToPDF,
  exportToJSON,
};
