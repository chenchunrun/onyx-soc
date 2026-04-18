"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { toast } from "@/hooks/useToast";

export default function EEFeatureRedirect() {
  const router = useRouter();

  useEffect(() => {
    toast.error(
      "This feature is not enabled for the current deployment or access level."
    );
    router.replace("/app");
  }, [router]);

  return null;
}
