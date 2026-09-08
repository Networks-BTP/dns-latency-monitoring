import {BarChart,Bar,XAxis,YAxis,CartesianGrid,Tooltip,ResponsiveContainer,Legend} from "recharts";
export function GroupComparison({data,labelA,labelB}:{data:{group:string;a:number;b:number}[];labelA:string;labelB:string}){
 return <ResponsiveContainer width="100%" height={360}>
  <BarChart data={data} margin={{top:6,right:12,left:0,bottom:56}}>
   <CartesianGrid strokeDasharray="3 3"/>
   <XAxis dataKey="group" angle={-32} textAnchor="end" interval={0} height={70} tick={{fontSize:12}}/>
   <YAxis unit=" ms" tick={{fontSize:12}}/>
   <Tooltip/>
   <Legend/>
   <Bar dataKey="a" name={labelA} fill="#111c25"/>
   <Bar dataKey="b" name={labelB} fill="#5b8def"/>
  </BarChart>
 </ResponsiveContainer>
}
