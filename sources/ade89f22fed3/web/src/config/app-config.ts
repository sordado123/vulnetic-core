import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Vulnetic",
  version: packageJson.version,
  copyright: `© ${currentYear}, Vulnetic.`,
  meta: {
    title: "Vulnetic — Security Workspace",
    description: "Remote security testing, execution review and reproducible evidence in one workspace.",
  },
};
