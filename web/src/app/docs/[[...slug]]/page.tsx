import Link from "next/link";
import * as SettingsLayouts from "@/layouts/settings-layouts";
import Card from "@/refresh-components/cards/Card";
import Text from "@/refresh-components/texts/Text";
import { Section } from "@/layouts/general-layouts";
import { SvgBookOpen, SvgExternalLink } from "@opal/icons";
import { Button } from "@opal/components";

const LOCAL_DOC_LINKS = [
  {
    title: "系统信息",
    description: "查看当前实例版本、运行环境与基础信息。",
    href: "/admin/systeminfo",
  },
  {
    title: "安全平台",
    description: "查看当前安全平台能力、运行状态与收口项。",
    href: "/admin/security-platform",
  },
  {
    title: "Prompt Presets",
    description: "查看和管理提示词样板与同步状态。",
    href: "/admin/prompt-presets",
  },
  {
    title: "Skills 管理",
    description: "查看已导入技能、权限等级与运行配置。",
    href: "/admin/skills",
  },
  {
    title: "Document Sets",
    description: "查看知识库集合、连接器和同步状态。",
    href: "/admin/documents/sets",
  },
];

export default async function LocalDocsPage({
  params,
}: {
  params: Promise<{ slug?: string[] }>;
}) {
  const resolvedParams = await params;
  const slug = resolvedParams.slug ?? [];
  const requestedPath = slug.length ? `/docs/${slug.join("/")}` : "/docs";

  return (
    <SettingsLayouts.Root width="md">
      <SettingsLayouts.Header
        icon={SvgBookOpen}
        title="Local Documentation"
        description="This instance now keeps documentation links on-box by default. Use the local navigation below."
      />

      <SettingsLayouts.Body>
        <Card className="p-5">
          <Section flexDirection="column" gap={1} alignItems="start">
            <Text text03 secondaryBody>
              Requested docs path: {requestedPath}
            </Text>
            <Text text03>
              The original documentation link has been intercepted by this local
              instance. If you have not mirrored the full docs set yet, use the
              local admin surfaces below as the primary reference.
            </Text>
          </Section>
        </Card>

        <div className="grid gap-4 md:grid-cols-2">
          {LOCAL_DOC_LINKS.map((item) => (
            <Card key={item.href} className="p-5">
              <Section flexDirection="column" gap={0.75} alignItems="start">
                <Text headingH3>{item.title}</Text>
                <Text text03 secondaryBody>
                  {item.description}
                </Text>
                <Button href={item.href} icon={SvgExternalLink}>
                  Open
                </Button>
              </Section>
            </Card>
          ))}
        </div>

        {slug.length > 0 && (
          <Card className="p-5">
            <Section flexDirection="column" gap={0.75} alignItems="start">
              <Text headingH3>Path Mapping</Text>
              <Text text03 secondaryBody>
                The requested documentation path does not yet have a dedicated
                local mirror.
              </Text>
              <Text text03>
                If this path matters operationally, add a matching local page
                or mirror it into the knowledge base index.
              </Text>
              <Link href="/admin/systeminfo" className="underline text-sm">
                Go to local system info
              </Link>
            </Section>
          </Card>
        )}
      </SettingsLayouts.Body>
    </SettingsLayouts.Root>
  );
}
