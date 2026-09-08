import type {Dataset,NormalizedQuery} from "../types/dns";
export function allQueries(d:Dataset[]){return d.flatMap(x=>x.queries)}
export function uniqueDomains(q:NormalizedQuery[]){return [...new Set(q.map(x=>x.domain))].sort()}
export function uniqueResolvers(q:NormalizedQuery[]){return [...new Set(q.map(x=>x.resolver))].sort()}
