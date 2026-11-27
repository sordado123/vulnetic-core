// Schedule after completion, abort on disposal, and stop network work in hidden tabs.
export function poll(load:(signal:AbortSignal)=>Promise<unknown>|void,delay:number):()=>void{
 let stopped=false,running=false;let timer:ReturnType<typeof setTimeout>|undefined;let controller:AbortController|null=null;
 const run=async()=>{if(stopped||running||document.hidden)return;running=true;controller=new AbortController();try{await load(controller.signal)}catch(e){if(!controller.signal.aborted)console.warn("Refresh failed; retrying on next poll")}finally{running=false;if(!stopped&&!document.hidden)timer=setTimeout(run,delay)}};
 const visible=()=>{clearTimeout(timer);if(document.hidden)controller?.abort();else void run()};document.addEventListener("visibilitychange",visible);void run();
 return()=>{stopped=true;clearTimeout(timer);controller?.abort();document.removeEventListener("visibilitychange",visible)};
}
