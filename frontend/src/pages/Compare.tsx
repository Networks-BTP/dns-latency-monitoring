import {useMemo,useState} from "react";
import type {Dataset,NormalizedQuery} from "../types/dns";
import {PageHeader} from "../components/PageHeader";
import {MetricCard} from "../components/MetricCard";
import {ChartCard} from "../components/ChartCard";
import {GroupComparison} from "../charts/GroupComparison";
import {mean,median,percentile,formatMs} from "../parser/statistics";

type ParamKey="domain"|"resolver"|"queryType"|"queryClass"|"rcode"|"interfaceName"|"clientIp"|"serverPort"|"sourceFile"|"timeout";

const PARAMS:{key:ParamKey;label:string;get:(q:NormalizedQuery)=>string}[]=[
 {key:"domain",label:"Domain",get:q=>q.domain},
 {key:"resolver",label:"Resolver",get:q=>q.resolver},
 {key:"queryType",label:"Query type (A, AAAA, MX...)",get:q=>q.queryType},
 {key:"queryClass",label:"Query class (IN, CH, HS...)",get:q=>q.queryClass},
 {key:"rcode",label:"Response code (RCODE)",get:q=>q.rcode},
 {key:"interfaceName",label:"Interface",get:q=>q.interfaceName},
 {key:"clientIp",label:"Client IP",get:q=>q.clientIp},
 {key:"serverPort",label:"Server port",get:q=>String(q.serverPort)},
 {key:"sourceFile",label:"Source file",get:q=>q.sourceFile},
 {key:"timeout",label:"Timeout status",get:q=>q.timeout?"Timeout":"Answered"},
];

function statsOf(v:number[]){return {avg:mean(v),p50:median(v),p95:percentile(v,.95),p99:percentile(v,.99)}}

export function Compare({datasets}:{datasets:Dataset[]}){
 const [a,setA]=useState(datasets[0]?.id||"");
 const [b,setB]=useState(datasets[1]?.id||datasets[0]?.id||"");
 const [paramKey,setParamKey]=useState<ParamKey>("domain");
 const [search,setSearch]=useState("");
 const [minCount,setMinCount]=useState(1);

 const da=datasets.find(d=>d.id===a),db=datasets.find(d=>d.id===b);
 const labelA=da?da.fileName:"A",labelB=db?db.fileName:"B";
 const param=PARAMS.find(p=>p.key===paramKey)||PARAMS[0];

 const sa=statsOf(da?.queries.map(q=>q.latencyMs)||[]);
 const sb=statsOf(db?.queries.map(q=>q.latencyMs)||[]);

 const rows=useMemo(()=>{
  if(!da||!db)return [];
  const groupBy=(qs:NormalizedQuery[])=>{
   const m=new Map<string,NormalizedQuery[]>();
   qs.forEach(q=>{const k=param.get(q);m.set(k,[...(m.get(k)||[]),q])});
   return m;
  };
  const ma=groupBy(da.queries),mb=groupBy(db.queries);
  const keys=new Set([...ma.keys(),...mb.keys()]);
  return [...keys].map(key=>{
   const qa=ma.get(key)||[],qb=mb.get(key)||[];
   const va=qa.map(q=>q.latencyMs),vb=qb.map(q=>q.latencyMs);
   const avgA=mean(va),avgB=mean(vb);
   return {key,countA:qa.length,countB:qb.length,avgA,avgB,delta:avgB-avgA};
  }).filter(r=>r.countA+r.countB>=minCount)
   .filter(r=>r.key.toLowerCase().includes(search.toLowerCase()))
   .sort((x,y)=>Math.abs(y.delta)-Math.abs(x.delta));
 },[da,db,param,search,minCount]);

 const chartData=useMemo(()=>rows.slice(0,12).map(r=>({group:r.key,a:Number(r.avgA.toFixed(2)),b:Number(r.avgB.toFixed(2))})),[rows]);

 return <div>
  <PageHeader title="Compare" description="Compare two imported runs on whichever parameter you choose — domain, resolver, query type, RCODE, and more."/>

  <div className="compare-selects">
   <label>Dataset A
    <select value={a} onChange={e=>setA(e.target.value)}>
     {datasets.map(d=><option key={d.id} value={d.id}>{d.fileName}</option>)}
    </select>
   </label>
   <label>Dataset B
    <select value={b} onChange={e=>setB(e.target.value)}>
     {datasets.map(d=><option key={d.id} value={d.id}>{d.fileName}</option>)}
    </select>
   </label>
   <label>Compare by
    <select value={paramKey} onChange={e=>setParamKey(e.target.value as ParamKey)}>
     {PARAMS.map(p=><option key={p.key} value={p.key}>{p.label}</option>)}
    </select>
   </label>
  </div>

  <div className="metric-grid compact">
   <MetricCard label="Average" value={`${formatMs(sa.avg)} / ${formatMs(sb.avg)}`} hint="A / B"/>
   <MetricCard label="P50" value={`${formatMs(sa.p50)} / ${formatMs(sb.p50)}`} hint="A / B"/>
   <MetricCard label="P95" value={`${formatMs(sa.p95)} / ${formatMs(sb.p95)}`} hint="A / B"/>
   <MetricCard label="P99" value={`${formatMs(sa.p99)} / ${formatMs(sb.p99)}`} hint="A / B"/>
  </div>

  {chartData.length>0&&
   <ChartCard title={`Top differences by ${param.label.toLowerCase()} (largest |delta| first)`}>
    <GroupComparison data={chartData} labelA={labelA} labelB={labelB}/>
   </ChartCard>
  }

  {rows.length>0&&<div className="panel table-wrap">
   <div className="toolbar">
    <h2 style={{margin:0}}>{param.label} comparison</h2>
    <div className="toolbar-controls">
     <input placeholder={`Search ${param.label.toLowerCase()}...`} value={search} onChange={e=>setSearch(e.target.value)}/>
     <label className="inline-filter">Min queries
      <input type="number" min={1} value={minCount} onChange={e=>setMinCount(Math.max(1,Number(e.target.value)||1))}/>
     </label>
     <span>{rows.length} rows</span>
    </div>
   </div>
   <table>
    <thead><tr>
     <th>{param.label}</th><th>A queries</th><th>B queries</th><th>A average</th><th>B average</th><th>Delta B − A</th>
    </tr></thead>
    <tbody>
     {rows.slice(0,200).map(r=><tr key={r.key}>
      <td><strong>{r.key}</strong></td>
      <td>{r.countA}</td>
      <td>{r.countB}</td>
      <td>{r.countA?formatMs(r.avgA):"—"}</td>
      <td>{r.countB?formatMs(r.avgB):"—"}</td>
      <td className={r.delta>0?"delta-pos":r.delta<0?"delta-neg":""}>{r.countA&&r.countB?formatMs(r.delta):"—"}</td>
     </tr>)}
    </tbody>
   </table>
  </div>}
 </div>
}
