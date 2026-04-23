"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { ConnectorOperationalAlert } from "@/lib/types";
import { timeAgo } from "@/lib/time";
import { FiAlertTriangle, FiClock, FiTrash2 } from "react-icons/fi";
import { getSourceDisplayName } from "@/lib/sources";
import Truncated from "@/refresh-components/texts/Truncated";

function getAlertSeverityLabel(alert: ConnectorOperationalAlert): string {
  if (alert.operational_stuck) {
    return "Stuck";
  }
  if (alert.operational_error) {
    return "Error";
  }
  if (alert.operational_deleting) {
    return "Deleting";
  }
  return "Unknown";
}

function AlertTypeBadge({ alert }: { alert: ConnectorOperationalAlert }) {
  if (alert.operational_stuck) {
    return (
      <Badge variant="secondary" icon={FiClock}>
        Stuck
      </Badge>
    );
  }
  if (alert.operational_error) {
    return (
      <Badge variant="destructive" icon={FiAlertTriangle}>
        Error
      </Badge>
    );
  }
  return (
    <Badge variant="secondary" icon={FiTrash2}>
      Deleting
    </Badge>
  );
}

export function OperationalAlertsPanel({
  alerts,
  isLoading,
}: {
  alerts: ConnectorOperationalAlert[] | undefined;
  isLoading: boolean;
}) {
  if (isLoading) {
    return (
      <div className="mb-6 rounded-lg border border-border p-4">
        <p className="text-sm text-muted-foreground">
          Loading operational alerts...
        </p>
      </div>
    );
  }

  if (!alerts || alerts.length === 0) {
    return (
      <div className="mb-6 rounded-lg border border-border bg-green-50/30 p-4 dark:bg-green-950/20">
        <p className="text-sm">No operational alerts detected.</p>
      </div>
    );
  }

  return (
    <div className="mb-6 rounded-lg border border-border">
      <div className="border-b border-border px-4 py-3">
        <p className="font-semibold">Operational Alerts</p>
        <p className="text-sm text-muted-foreground">
          Showing {alerts.length} connector alert
          {alerts.length > 1 ? "s" : ""} (`stuck`, `error`, `deleting`)
        </p>
      </div>
      <div className="divide-y divide-border">
        {alerts.map((alert) => (
          <Link
            key={alert.cc_pair_id}
            href={`/admin/connector/${alert.cc_pair_id}`}
            className="block px-4 py-3 hover:bg-accent-background"
          >
            <div className="flex items-center gap-3">
              <AlertTypeBadge alert={alert} />
              <p className="text-sm font-medium">{getAlertSeverityLabel(alert)}</p>
              <p className="text-xs text-muted-foreground">
                {getSourceDisplayName(alert.source)}
              </p>
              <p className="text-xs text-muted-foreground">
                Last success: {timeAgo(alert.last_success) || "Never"}
              </p>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <p className="text-sm font-medium">
                <Truncated>{alert.name}</Truncated>
              </p>
              {alert.reasons.slice(0, 3).map((reason) => (
                <Badge key={reason} variant="default">
                  {reason}
                </Badge>
              ))}
            </div>
            {alert.last_error_message && (
              <p className="mt-1 line-clamp-2 text-xs text-muted-foreground">
                {alert.last_error_message}
              </p>
            )}
          </Link>
        ))}
      </div>
    </div>
  );
}
