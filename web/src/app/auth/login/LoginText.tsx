"use client";

import React, { useContext } from "react";
import { SettingsContext } from "@/providers/SettingsProvider";
import Text from "@/refresh-components/texts/Text";

export default function LoginText() {
  const settings = useContext(SettingsContext);
  return (
    <div className="w-full flex flex-col ">
      <Text as="p" headingH2 text05>
        欢迎使用{" "}
        {(settings && settings?.enterpriseSettings?.application_name) || "CMSOC 智能安全底座"}
      </Text>
      <Text as="p" text03 mainUiMuted>
        企业级智能安全运营与知识赋能平台
      </Text>
    </div>
  );
}
