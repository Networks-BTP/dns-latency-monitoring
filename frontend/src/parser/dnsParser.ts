import type {Dataset,DnsRunJson,NormalizedQuery} from "../types/dns";

function rec(v:unknown):Record<string,unknown>{return v&&typeof v==="object"&&!Array.isArray(v)?v as Record<string,unknown>:{}}
function arr(v:unknown):unknown[]{return Array.isArray(v)?v:[]}
function str(v:unknown,fallback=""):string{return typeof v==="string"?v:fallback}
function num(v:unknown,fallback=0):number{return typeof v==="number"&&!Number.isNaN(v)?v:fallback}
function bool(v:unknown):boolean{return v===true}

/** A parsed DNS message (query or response) can arrive from several shapes across format versions. */
function firstQuestion(msg:Record<string,unknown>){
 const qs=arr(msg.questions), first=rec(qs[0]);
 return {
  name:str(first.name,"").replace(/\.$/,""),
  type:str(first.type_name,""),
  cls:str(first.class_name,""),
 };
}

/** Resolve the outbound query DNS message (qr=0) across format versions. */
function queryMessage(q:Record<string,unknown>):Record<string,unknown>{
 const newShape=rec(rec(q.query).parsed);            // new format: q.query.parsed
 if(Object.keys(newShape).length) return newShape;
 const oldShape=rec(rec(q.latency).parsed_query);     // old format: q.latency.parsed_query
 return oldShape;
}

/** Resolve the DNS response message (qr=1), if one was received, across format versions. */
function responseMessage(q:Record<string,unknown>):Record<string,unknown>{
 const newShape=rec(rec(q.response).parsed);                    // new format: q.response.parsed
 if(Object.keys(newShape).length) return newShape;
 const oldShape=rec(rec(rec(q.xdp).response).parsed);            // old format: q.xdp.response.parsed
 return oldShape;
}

function clientOf(q:Record<string,unknown>){
 const c=rec(q.client);                                          // new format: q.client.{ip,port}
 if(typeof c.ip==="string") return {ip:c.ip,port:num(c.port,0)};
 const l=rec(q.latency);                                         // old format: flat / latency fields
 return {ip:str(q.client_ip,str(l.client_ip,"Unknown")),port:num(q.client_port,num(l.client_port,0))};
}

function serverOf(q:Record<string,unknown>){
 const s=rec(q.server);                                          // new format: q.server.{ip,port}
 if(typeof s.ip==="string") return {ip:s.ip,port:num(s.port,53)};
 const l=rec(q.latency);                                         // old format: flat / latency fields
 return {ip:str(q.server_ip,str(l.server_ip,"Unknown")),port:num(q.server_port,num(l.server_port,53))};
}

export function parseDnsJson(text:string,fileName:string):Dataset{
 const j=JSON.parse(text) as DnsRunJson;
 const run=rec(j.run), raw=arr(j.queries) as Record<string,unknown>[];
 const pid=num(run.pid,0), iface=str(run.interface,"Unknown"), started=str(run.started_at,"");

 const queries:NormalizedQuery[]=raw.map((q,index)=>{
  const l=rec(q.latency);
  const client=clientOf(q), server=serverOf(q);
  const qMsg=queryMessage(q), rMsg=responseMessage(q);
  const qQuestion=firstQuestion(qMsg), rQuestion=firstQuestion(rMsg);
  const timeout=bool(l.is_timeout);

  const domain=qQuestion.name||rQuestion.name||"Unknown";
  const queryType=qQuestion.type||rQuestion.type||"UNKNOWN";
  const queryClass=qQuestion.cls||rQuestion.cls||"UNKNOWN";

  const rcode=str(rMsg.rcode_name)||str(qMsg.rcode_name)||str(l.rcode_name)||(timeout?"TIMEOUT":"UNKNOWN");
  const answerCount=num(rec(rMsg.counts).answers,num(l.answer_count,0));

  return {
   queryId:num(q.query_id,index),
   domain,resolver:server.ip,
   clientIp:client.ip,clientPort:client.port,serverPort:server.port,
   interfaceName:iface,startedAt:started,
   timestampNs:num(l.timestamp_ns,0),latencyMs:num(l.latency_ms,0),
   queryType,queryClass,rcode,timeout,answerCount,
   sourceFile:fileName,runPid:pid,
  };
 });

 return {id:`${fileName}-${pid}-${Date.now()}-${Math.random()}`,fileName,runPid:pid,interfaceName:iface,startedAt:started,queryCount:queries.length,queries};
}
