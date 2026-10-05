import fixturePayload from '../../../demo/contoso-health.json'
import { parseSnapshot } from '../data/validation'

export const demoSnapshot = parseSnapshot(fixturePayload)
