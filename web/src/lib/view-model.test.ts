import { describe, expect, it } from 'vitest'
import { demoSnapshot } from '../test/fixture'
import { createAtlasViewModel, selectVisibleAtlas } from './view-model'

const filters = { query: '', severity: 'all' as const, type: 'all', attackPathId: 'all' }

describe('AtlasViewModel', () => {
  it('builds reusable risk, relationship and membership indexes', () => {
    const model = createAtlasViewModel(demoSnapshot)
    expect(model.resourceById.size).toBe(demoSnapshot.resources.length)
    expect(model.riskByResourceId.get('app-clinical-api')).toBe(96)
    expect(model.neighborsByResourceId.get('app-clinical-api')).toContain('identity-clinical-api')
    expect(model.pathsByResourceId.get('app-clinical-api')).toHaveLength(1)
  })

  it('keeps positions stable while filtering and enforces visible limits', () => {
    const model = createAtlasViewModel(demoSnapshot)
    const originalPosition = model.positionByResourceId.get('app-clinical-api')
    const filtered = selectVisibleAtlas(model, { ...filters, query: 'clinical' }, {
      mode: 'overview', selectedResourceId: null, pathId: null, limit: 2,
    })
    expect(filtered.resources).toHaveLength(2)
    expect(filtered.truncated).toBe(true)
    expect(model.positionByResourceId.get('app-clinical-api')).toEqual(originalPosition)
  })

  it('creates focused attack-path and neighborhood views', () => {
    const model = createAtlasViewModel(demoSnapshot)
    const path = demoSnapshot.attackPaths[0]!
    const pathView = selectVisibleAtlas(model, filters, {
      mode: 'attack-path', selectedResourceId: null, pathId: path.id, limit: 300,
    })
    expect(pathView.resources.map((resource) => resource.id)).toEqual(path.resourceIds)

    const neighborhood = selectVisibleAtlas(model, filters, {
      mode: 'neighborhood', selectedResourceId: 'app-clinical-api', pathId: null, limit: 300,
    })
    expect(neighborhood.visibleResourceIds).toContain('app-clinical-api')
    expect(neighborhood.visibleResourceIds).toContain('identity-clinical-api')
  })
})
