export function formatCurrency(amount: number, currency: string): string {
  const formatter = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    minimumFractionDigits: 2,
  });
  return formatter.format(amount);
}

export function formatDate(
  date: Date,
  format: "short" | "long" | "iso" = "long",
): string {
  if (format === "iso") {
    return date.toISOString().split("T")[0];
  }

  const options: Intl.DateTimeFormatOptions =
    format === "short"
      ? { month: "2-digit", day: "2-digit", year: "numeric" }
      : {
          month: "2-digit",
          day: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        };

  return new Intl.DateTimeFormat("en-US", options).format(date);
}

export function formatPhoneNumber(phone: string): string {
  const digits = phone.replace(/\D/g, "");
  if (digits.length >= 10) {
    const core = digits.slice(-10);
    const area = core.slice(0, 3);
    const prefix = core.slice(3, 6);
    const line = core.slice(6);
    return `(${area}) ${prefix}-${line}`;
  }
  return phone;
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      // Toggle quoting; doubled quotes inside quoted fields are collapsed
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  values.push(current);
  return values.map((v) => v.trim());
}

export function parseCSV(csv: string): Array<Record<string, string>> {
  const lines = csv.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) return [];

  const headers = parseCsvLine(lines[0]);
  const rows = lines.slice(1);

  return rows.map((row) => {
    const values = parseCsvLine(row);
    const record: Record<string, string> = {};
    headers.forEach((header, idx) => {
      record[header] = values[idx] ?? "";
    });
    return record;
  });
}

export function stringToSlug(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^-+|-+$/g, "");
}
