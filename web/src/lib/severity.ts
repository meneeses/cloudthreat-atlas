import type { Severity } from '../types'

export const severityOrder: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
}

export const severityColor: Record<Severity, string> = {
  critical: '#ff4d6d',
  high: '#ff8b3d',
  medium: '#ffc857',
  low: '#38bdf8',
  info: '#94a3b8',
}

export function formatSeverity(severity: Severity): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

export function calculateRiskScore(scores: number[]): number {
  if (scores.length === 0) return 0
  const weighted = scores.reduce((total, score) => total + score, 0) / scores.length
  return Math.round(Math.min(100, weighted))
}
