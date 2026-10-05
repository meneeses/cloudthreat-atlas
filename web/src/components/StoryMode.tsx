import type { AttackPath, ResourceNode } from '../types'
import { formatSeverity } from '../lib/severity'

interface StoryModeProps {
  paths: AttackPath[]
  nodes: ResourceNode[]
  activePath: AttackPath | null
  storyStep: number
  playing: boolean
  onStart: (pathId: string) => void
  onStop: () => void
  onPrevious: () => void
  onNext: () => void
  onTogglePlaying: () => void
}

export function StoryMode({
  paths,
  nodes,
  activePath,
  storyStep,
  playing,
  onStart,
  onStop,
  onPrevious,
  onNext,
  onTogglePlaying,
}: StoryModeProps) {
  if (!activePath) {
    return (
      <section className="story-launcher" aria-label="Attack path stories">
        <div className="story-launcher-copy">
          <span className="story-icon" aria-hidden="true">▶</span>
          <div>
            <span className="eyebrow">ATTACK PATH STORY MODE</span>
            <strong>See how an attacker moves through the environment</strong>
          </div>
        </div>
        <div className="story-path-buttons">
          {paths.map((path, index) => (
            <button key={path.id} type="button" onClick={() => onStart(path.id)}>
              <span className={`path-number path-${path.severity}`}>{index + 1}</span>
              <span>{path.title}</span>
              <span aria-hidden="true">→</span>
            </button>
          ))}
        </div>
      </section>
    )
  }

  const currentNodeId = activePath.resourceIds[Math.max(0, storyStep)]
  const currentNode = nodes.find((node) => node.id === currentNodeId)
  const atStart = storyStep <= 0
  const atEnd = storyStep >= activePath.resourceIds.length - 1
  const currentNarrative = storyStep === 0
    ? activePath.description
    : activePath.steps[storyStep - 1]?.narrative ?? activePath.description

  return (
    <section className="story-player" aria-label={`Story mode: ${activePath.title}`}>
      <div className="story-progress" aria-hidden="true">
        {activePath.resourceIds.map((nodeId, index) => (
          <span
            key={nodeId}
            className={index < storyStep ? 'complete' : index === storyStep ? 'current' : ''}
          />
        ))}
      </div>

      <div className="story-player-main">
        <div className="story-context">
          <span className={`severity-badge severity-${activePath.severity}`}>
            {formatSeverity(activePath.severity)} path
          </span>
          <strong>{activePath.title}</strong>
          <span>Step {storyStep + 1} of {activePath.resourceIds.length}</span>
        </div>

        <div className="story-current-step" aria-live="polite">
          <span className="step-pulse" aria-hidden="true" />
          <div>
            <span className="eyebrow">CURRENT HOP</span>
            <strong>{currentNode?.name ?? currentNodeId}</strong>
            <small>{currentNarrative}</small>
          </div>
        </div>

        <div className="story-controls">
          <button type="button" onClick={onPrevious} disabled={atStart} aria-label="Previous step">←</button>
          <button
            className="play-button"
            type="button"
            onClick={onTogglePlaying}
            aria-label={playing ? 'Pause story' : 'Play story'}
          >
            {playing ? 'Ⅱ' : '▶'}
          </button>
          <button type="button" onClick={onNext} disabled={atEnd} aria-label="Next step">→</button>
          <button className="exit-story" type="button" onClick={onStop}>Exit story</button>
        </div>
      </div>
    </section>
  )
}
