# On-Call Contact Sheet

Use this roster to escalate incidents. Keep phone numbers and escalation channels current.

| Role            | Name           | Timezone | Phone           | Slack   | Backup      |
| --------------- | -------------- | -------- | --------------- | ------- | ----------- |
| Primary On-Call | Jordan Alvarez | ET       | +1-202-555-0114 | @jordan | Priya Shah  |
| Secondary       | Priya Shah     | PT       | +1-415-555-0142 | @priya  | Marcus Lee  |
| Tertiary        | Marcus Lee     | CT       | +1-312-555-0198 | @marcus | Samir Patel |
| Duty Manager    | Samir Patel    | ET       | +1-646-555-0133 | @samir  | CTO         |

## Escalation Steps

1. Page Primary via PagerDuty/phone.
2. If no response in 10 minutes, page Secondary.
3. If still no response in 10 minutes, escalate to Duty Manager.
4. For SEV-1, notify #incidents and Exec contact (CTO).

## Communication Channels

- Slack: #incidents (primary), #engineering (secondary)
- Phone bridge: +1-650-555-0200 PIN 4455
- Zoom bridge: https://infamousfreight.zoom.us/j/oncall

## Update Process

- Review this sheet weekly during the ops sync.
- Update phone numbers after each rotation change.
- Verify PagerDuty schedules match this roster.

## Additional Notes

- Keep devices with cellular failover during on-call.
- Ensure access to Grafana, PagerDuty, AWS, and database tooling.
- Record post-incident follow-ups in ON_CALL_RUNBOOK.md postmortem section.
