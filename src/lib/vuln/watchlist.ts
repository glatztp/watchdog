export const PACKAGE_WATCHLIST: Record<string, string[]> = {
  "ansi-regex": ["6.2.1"],
  "ansi-styles": ["6.2.2"],
  axios: ["1.14.1", "0.30.4"],
  backslash: ["0.2.1"],
  bip40: ["1.0.0", "1.0.6"],
  "bitcoin-lib-js": ["7.2.1"],
  "bitcoin-main-lib": ["7.0.0", "7.2.0"],
  "@bitwarden/cli": ["2026.4.0"],
  "@cap-js/db-service": ["2.10.1"],
  "@cap-js/postgres": ["2.2.2"],
  "@cap-js/sqlite": ["2.2.2"],
  chalk: ["5.6.1"],
  "chalk-template": ["1.1.1"],
  coa: ["2.0.3", "2.0.4", "2.1.1", "2.1.3", "3.1.3"],
  color: ["5.0.1"],
  "color-convert": ["3.1.1"],
  "color-name": ["2.0.1"],
  "color-string": ["2.1.1"],
  colors: ["1.4.1", "1.4.2", "1.4.44-liberty-2"],
  debug: ["4.4.2"],
  "error-ex": ["1.3.3"],
  "eslint-config-prettier": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
  "event-stream": ["3.3.6"],
  faker: ["6.6.6"],
  "flatmap-stream": ["0.1.1"],
  "has-ansi": ["6.0.1"],
  "is-arrayish": ["0.3.3"],
  mbt: ["1.2.48"],
  "node-ipc": ["10.1.1", "10.1.2"],
  nx: [
    "20.9.0",
    "20.10.0",
    "20.11.0",
    "20.12.0",
    "21.5.0",
    "21.6.0",
    "21.7.0",
    "21.8.0",
  ],
  "plain-crypto-js": ["4.2.1"],
  rc: ["1.2.9", "1.3.9", "2.3.9"],
  "simple-swizzle": ["0.2.3"],
  "slice-ansi": ["7.1.1"],
  "strip-ansi": ["7.1.1"],
  "supports-color": ["10.2.1"],
  "supports-hyperlinks": ["4.1.1"],
  "ua-parser-js": ["0.7.29", "0.8.0", "1.0.0"],
  "wrap-ansi": ["9.0.1"],
};

export function getWatchlistDependencies(repo: any): any[] {
  const deps = [];

  for (const [name, versions] of Object.entries(PACKAGE_WATCHLIST)) {
    for (const version of versions) {
      deps.push({
        name,
        version,
        type: "dependency",
        repo,
      });
    }
  }

  return deps;
}
