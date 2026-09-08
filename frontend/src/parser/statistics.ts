export function mean(v:number[]){return v.length?v.reduce((a,b)=>a+b,0)/v.length:0}
export function percentile(v:number[],p:number){if(!v.length)return 0;const s=[...v].sort((a,b)=>a-b),i=(s.length-1)*p,l=Math.floor(i),u=Math.ceil(i);return l===u?s[l]:s[l]+(s[u]-s[l])*(i-l)}
export function median(v:number[]){return percentile(v,.5)}
export function min(v:number[]){return v.length?Math.min(...v):0}
export function max(v:number[]){return v.length?Math.max(...v):0}
export function formatMs(v:number){return `${v.toFixed(2)} ms`}
