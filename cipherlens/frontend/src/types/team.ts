export interface Team {
  id: string;
  name: string;
  description: string | null;
  createdAt: string | null;
  memberIds: string[] | null;
  memberCount: number;
  leadIds: string[] | null;
}

export interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: string;
  organization_id: string | number | null;
}
