#!/usr/bin/env node
import('../dist/cli.js').catch((err) => {
  console.error('Failed to start mcp-audit:', err);
  process.exit(10);
});
