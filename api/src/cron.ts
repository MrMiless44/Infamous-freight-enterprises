import cron from "node-cron";
import { weeklySummary } from "./automation/weekly";

cron.schedule("0 9 * * 1", weeklySummary);
