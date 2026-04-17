export interface AppInputBarSubmitPayload {
  message: string;
  activeSkillKeys: string[];
  skillTargets: string[];
  skillApprovalReference: string | null;
}
