export interface YaraRule {
  id: string;
  name: string;
  category: "Botnet" | "Backdoor" | "Persistence" | "Suspicious Command" | "Reverse Shell" | "Credential Leak";
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
  strings: string[];
  regexes?: RegExp[];
}

export interface YaraMatch {
  ruleId: string;
  ruleName: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
  filePath: string;
  matchedString: string;
}
