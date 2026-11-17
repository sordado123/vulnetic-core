const TOKEN_KEY="vulnetic_token";
export interface CurrentUser {id:string;name:string;username:string;email:string;avatar:string;role:string}
let user:CurrentUser|null=null;
let checking:Promise<boolean>|null=null;
async function session(token?:string):Promise<boolean>{
 const r=await fetch("/api/auth/session",{method:token?"POST":"GET",cache:"no-store",headers:{"X-Vulnetic-Request":"1",...(token?{Authorization:`Bearer ${token}`}:{})}});
 if(r.status===401){user=null;return false}if(!r.ok)throw new Error("Session service unavailable. Retry without signing out.");
 const v=await r.json();user={id:String(v.id),name:v.email||"Vulnetic",username:v.email||"Vulnetic",email:v.email||"",avatar:"",role:v.role};return true;
}
export const auth={
 getToken():string|null{return null},
 async setToken(token:string):Promise<void>{if(!await session(token))throw new Error("Session expired");localStorage.removeItem(TOKEN_KEY)},
 async bootstrap():Promise<boolean>{
 if(process.env.NEXT_PUBLIC_MOCK==="1")return true;
 if(!checking)checking=(async()=>{const legacy=localStorage.getItem(TOKEN_KEY);if(legacy){await this.setToken(legacy);return true}return session()})().finally(()=>{checking=null});return checking;
 },
 async clearToken():Promise<void>{const r=await fetch("/api/auth/logout",{method:"POST",headers:{"X-Vulnetic-Request":"1"}});if(!r.ok)throw new Error("Sign out failed; retry");localStorage.removeItem(TOKEN_KEY);user=null},
 getCurrentUser():CurrentUser|null{return user}
};
