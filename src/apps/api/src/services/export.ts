import { Parser } from 'json2csv';
import PDFDocument from 'pdfkit';
import { Readable } from 'stream';
import type { Response } from 'express';

interface ExportOptions {
  filename?: string;
  fields?: string[];
}

interface Shipment {
  id: string;
  status: string;
  origin: string;
  destination: string;
  driver?: { name: string };
  createdAt: string;
  updatedAt: string;
  [key: string]: unknown;
}

/**
 * Export Service
 * Handles exporting data to CSV, PDF, and JSON formats
 */
export class ExportService {
  /**
   * Export data to CSV format
   */
  static async exportToCSV(
    data: any[],
    options: ExportOptions = {}
  ): Promise<string> {
    if (!data || data.length === 0) {
      return '';
    }

    const fields = options.fields || Object.keys(data[0]);

    const parser = new Parser({ fields });
    return parser.parse(data);
  }

  /**
   * Send CSV response to client
   */
  static sendCSV(
    res: Response,
    data: any[],
    filename: string = 'export.csv'
  ): void {
    try {
      const csv = this.exportToCSV(data);

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename}"`
      );
      res.send(csv);
    } catch (error) {
      res.status(500).json({ error: 'Failed to generate CSV' });
    }
  }

  /**
   * Export shipments to PDF with summary
   */
  static async exportToPDF(
    res: Response,
    shipments: Shipment[],
    filename: string = 'shipments.pdf'
  ): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument();

        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader(
          'Content-Disposition',
          `attachment; filename="${filename}"`
        );

        // Pipe to response
        doc.pipe(res);

        // Title
        doc.fontSize(20).font('Helvetica-Bold').text('Shipments Report', {
          align: 'center',
        });

        doc.moveDown();

        // Summary
        doc
          .fontSize(12)
          .font('Helvetica')
          .text(
            `Generated: ${new Date().toLocaleString()}`,
            { align: 'right' }
          );

        doc.moveDown();

        // Stats
        const stats = this.calculateShipmentStats(shipments);
        doc.fontSize(14).font('Helvetica-Bold').text('Summary Statistics');
        doc.fontSize(11).font('Helvetica');
        doc.text(`Total Shipments: ${stats.total}`);
        doc.text(`In Transit: ${stats.inTransit}`);
        doc.text(`Delivered: ${stats.delivered}`);
        doc.text(`Pending: ${stats.pending}`);

        doc.moveDown();

        // Table header
        doc
          .fontSize(12)
          .font('Helvetica-Bold')
          .text('Shipment Details', { underline: true });

        doc.moveDown(0.5);

        // Table data
        doc.fontSize(10).font('Helvetica');

        const colX = { id: 50, status: 150, origin: 250, destination: 350 };
        const lineHeight = 15;

        // Header row
        doc.text('ID', colX.id, doc.y);
        doc.text('Status', colX.status, doc.y - lineHeight);
        doc.text('Origin', colX.origin, doc.y - lineHeight);
        doc.text('Destination', colX.destination, doc.y - lineHeight);

        doc.moveDown();

        // Data rows
        shipments.slice(0, 20).forEach((shipment) => {
          const y = doc.y;

          if (y > 700) {
            doc.addPage();
          }

          doc.text(
            shipment.id.substring(0, 8),
            colX.id,
            doc.y
          );
          doc.text(shipment.status, colX.status, doc.y - lineHeight);
          doc.text(shipment.origin, colX.origin, doc.y - lineHeight);
          doc.text(
            shipment.destination,
            colX.destination,
            doc.y - lineHeight
          );

          doc.moveDown();
        });

        if (shipments.length > 20) {
          doc.moveDown();
          doc.fontSize(10).text(
            `... and ${shipments.length - 20} more shipments`,
            { italics: true }
          );
        }

        // End document
        doc.end();

        doc.on('finish', () => resolve());
        doc.on('error', (error) => reject(error));
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Export data to JSON format
   */
  static async exportToJSON(data: any[]): Promise<string> {
    return JSON.stringify(data, null, 2);
  }

  /**
   * Send JSON response to client
   */
  static sendJSON(
    res: Response,
    data: any[],
    filename: string = 'export.json'
  ): void {
    try {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${filename}"`
      );
      res.json({
        meta: {
          exported: new Date().toISOString(),
          count: data.length,
        },
        data,
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to generate JSON' });
    }
  }

  /**
   * Calculate shipment statistics
   */
  private static calculateShipmentStats(shipments: Shipment[]): {
    total: number;
    inTransit: number;
    delivered: number;
    pending: number;
  } {
    return {
      total: shipments.length,
      inTransit: shipments.filter((s) => s.status === 'in_transit').length,
      delivered: shipments.filter((s) => s.status === 'delivered').length,
      pending: shipments.filter((s) => s.status === 'pending').length,
    };
  }

  /**
   * Flatten nested objects for CSV export
   */
  static flattenObject(obj: any, prefix = ''): any {
    const flattened: any = {};

    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        const newKey = prefix ? `${prefix}_${key}` : key;

        if (
          value &&
          typeof value === 'object' &&
          !Array.isArray(value) &&
          !(value instanceof Date)
        ) {
          Object.assign(this.flattenObject(value, newKey), flattened);
        } else {
          flattened[newKey] = value;
        }
      }
    }

    return flattened;
  }
}

export default ExportService;
