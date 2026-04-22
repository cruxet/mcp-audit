import type { Reporter } from './types.js';
import { prettyReporter } from './pretty.js';
import { jsonReporter } from './json.js';
import { sarifReporter } from './sarif.js';
import { markdownReporter } from './markdown.js';

export type ReporterFormat = 'pretty' | 'json' | 'sarif' | 'markdown';

export function getReporter(format: ReporterFormat): Reporter {
  switch (format) {
    case 'json':
      return jsonReporter;
    case 'sarif':
      return sarifReporter;
    case 'markdown':
      return markdownReporter;
    case 'pretty':
    default:
      return prettyReporter;
  }
}

export { prettyReporter, jsonReporter, sarifReporter, markdownReporter };
export type { Reporter };
