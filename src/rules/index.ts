import type { Rule } from './types.js';
import { commandAllowlistRule } from './command-allowlist.js';
import { argumentInjectionRule } from './argument-injection.js';
import { secretDetectionRule } from './secret-detection.js';
import { insecureTransportRule } from './insecure-transport.js';
import { environmentInjectionRule } from './environment-injection.js';
import { suspiciousPackageRule } from './suspicious-package.js';
import { configurationErrorRule } from './configuration-error.js';

export const allRules: Rule[] = [
  commandAllowlistRule,
  argumentInjectionRule,
  secretDetectionRule,
  insecureTransportRule,
  environmentInjectionRule,
  suspiciousPackageRule,
  configurationErrorRule,
];

export {
  commandAllowlistRule,
  argumentInjectionRule,
  secretDetectionRule,
  insecureTransportRule,
  environmentInjectionRule,
  suspiciousPackageRule,
  configurationErrorRule,
};
