from onyx.configs.app_configs import WEB_DOMAIN
from onyx.configs.constants import DocumentSource


_WEB_DOMAIN = WEB_DOMAIN.rstrip("/")

_LOCAL_SOURCE_ICON_PATHS: dict[str, str] = {
    DocumentSource.WEB.value: "/web.svg",
    DocumentSource.FILE.value: "/logo.png",
    DocumentSource.GOOGLE_SITES.value: "/GoogleSites.png",
    DocumentSource.SLACK.value: "/Slack.png",
    DocumentSource.GMAIL.value: "/Gmail.png",
    DocumentSource.GOOGLE_DRIVE.value: "/GoogleDrive.png",
    DocumentSource.GITHUB.value: "/Github.png",
    DocumentSource.GITLAB.value: "/Gitlab.png",
    DocumentSource.CONFLUENCE.value: "/Confluence.svg",
    DocumentSource.JIRA.value: "/Jira.svg",
    DocumentSource.NOTION.value: "/Notion.png",
    DocumentSource.ZENDESK.value: "/Zendesk.svg",
    DocumentSource.GONG.value: "/Gong.png",
    DocumentSource.LINEAR.value: "/Linear.png",
    DocumentSource.PRODUCTBOARD.value: "/Productboard.png",
    DocumentSource.SLAB.value: "/SlabLogo.png",
    DocumentSource.ZULIP.value: "/Zulip.png",
    DocumentSource.GURU.value: "/Guru.svg",
    DocumentSource.HUBSPOT.value: "/HubSpot.png",
    DocumentSource.DOCUMENT360.value: "/Document360.png",
    DocumentSource.BOOKSTACK.value: "/Bookstack.png",
    DocumentSource.OUTLINE.value: "/Outline.png",
    DocumentSource.LOOPIO.value: "/Loopio.png",
    DocumentSource.SHAREPOINT.value: "/Sharepoint.png",
    DocumentSource.REQUESTTRACKER.value: "/logo.png",
    DocumentSource.INGESTION_API.value: "/logo.png",
}


def _build_icon_url(path: str) -> str:
    return f"{_WEB_DOMAIN}{path}"


def source_to_github_img_link(source: DocumentSource) -> str | None:
    path = _LOCAL_SOURCE_ICON_PATHS.get(source) or "/logo.png"
    return _build_icon_url(path)
