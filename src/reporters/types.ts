import type { ScanResult } from '../scanner/index.js';

export interface Reporter {
  format: 'pretty' | 'json' | 'sarif' | 'markdown';
  render(result: ScanResult): string;
}
