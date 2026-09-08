export interface NormalizedQuery {
  queryId:number; domain:string; resolver:string; clientIp:string; clientPort:number; serverPort:number;
  interfaceName:string; startedAt:string; timestampNs:number; latencyMs:number;
  queryType:string; queryClass:string; rcode:string; timeout:boolean; answerCount:number;
  sourceFile:string; runPid:number;
}
export interface Dataset {
  id:string; fileName:string; runPid:number; interfaceName:string; startedAt:string;
  queryCount:number; queries:NormalizedQuery[];
}
export interface DnsRunJson {run?:Record<string,unknown>; queries?:Array<Record<string,unknown>>;}
export type View="overview"|"datasets"|"latency"|"domains"|"resolvers"|"compare"|"raw";
