"use client";

import AuthFlowContainer from "@/components/auth/AuthFlowContainer";
import { REGISTRATION_URL } from "@/lib/constants";
import { Button } from "@opal/components";
import Link from "next/link";
import { SvgImport } from "@opal/icons";

export default function Page() {
  return (
    <AuthFlowContainer>
      <div className="flex flex-col space-y-6">
        <h2 className="text-2xl font-bold text-text-900 text-center">
          未找到账号
        </h2>
        <p className="text-text-700 max-w-md text-center">
          我们在系统中未找到您的账号。如需访问 CMSOC 智能安全底座，请选择以下方式：
        </p>
        <ul className="list-disc text-left text-text-600 w-full pl-6 mx-auto">
          <li>等待管理员邀请加入已有团队</li>
          <li>创建新的组织</li>
        </ul>
        <div className="flex justify-center">
          <Button
            href={`${REGISTRATION_URL}/register`}
            width="full"
            icon={SvgImport}
          >
            创建新组织
          </Button>
        </div>
        <p className="text-sm text-text-500 text-center">
          使用其他邮箱已有账号？{" "}
          <Link
            href="/auth/login"
            className="text-action-link-05 hover:underline"
          >
            登录
          </Link>
        </p>
      </div>
    </AuthFlowContainer>
  );
}
